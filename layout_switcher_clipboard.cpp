#define UNICODE
#define _UNICODE

// кажемо Windows використовувати сучасний візуальний стиль (для віконця і кнопок)
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "bcrypt.lib")

#include <windows.h> // Windows API
#include <windowsx.h> // macro APIs and control APIs
#include <uxtheme.h> // для доступу до системної теми
#include <shellapi.h> // для роботи з піктограмою в системному лотку (треї)
#include <bcrypt.h>  // API (CNG) для шифрування
#include <strsafe.h> // Windows SDK designed to prevent security vulnerabilities
#include <cstdint>  // для uint
#include <wchar.h>  // для wmemcpy

#ifndef NT_SUCCESS  // макрос перевірки успішності функцій CNG (щоб не підмикати важкий ntstatus.h)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// =|=|= глобальні налаштування інтерфейсу =|=|=
struct AppSettings {
    int winWidth = 560;        // ширина головного вікна буфера
    int winHeight = 720;       // висота головного вікна
    int itemHeight = 90;       // висота однієї "картки" з текстом
    int itemGap = 8;           // відступ між картками
    int cornerRadius = 20;     // радіус заокруглення кутів вікна та карток
    int uiPreviewLength = 168; // скільки символів початку тексту показувати у прев'ю. TODO(!)
    int headerHeight = 32;     // висота верхньої "шапки" (за яку можна тягати вікно)
    int bottomHeight = 32;     // висота нижньої смужки для перетягування
};
AppSettings g_Config; // глобальний об'єкт конфігурації

// =|=|= налаштування трею та іконки =|=|=
#define WM_TRAYICON (WM_APP + 2) // кастомне повідомлення для обробки кліків у треї
#define IDI_APPICON 101          // id іконки в ресурсах (.rc файл)

// =|=|= налаштування пам'яті та безпеки =|=|=
#define LARGE_TEXT_THRESHOLD (16 * 1024) // якщо скопіювали більше 16 КБ за раз — скидаємо у файл
#define DISK_BLOCK_SIZE 16384 // 16 КБ блок на диску
#define RAM_BLOCK_SIZE 2048   // 2 КБ розмір структури в RAM
#define USER_KEY L"MySecretKey2026"  // пароль для генерації SHA-256 ключа під AES-256 криптографічне шифрування

#define DB_FILE_NAME L"custom_clipboard.bin"
#define DB_FOLDER_NAME L"ClipboardData"
#define DB_FOLDER_PATH L"ClipboardData\\"

// === синхронізація доступу до даних ===
SRWLOCK g_DataLock = SRWLOCK_INIT;
HANDLE g_hDbFile = INVALID_HANDLE_VALUE; // глобальний дескриптор для відкритого файлу БД

namespace DataFlags { // прапори даних про картку
    const uint8_t Empty     = 0;         // 0000 0000 (комірка вільна / Tombstone)
    const uint8_t Used      = 1 << 0;    // 0000 0001 (запис активний)
    const uint8_t CtrlC     = 1 << 1;    // 0000 0010 (системний буфер)
    const uint8_t Micro     = 1 << 2;    // 0000 0100 (мікротекст)
    const uint8_t Pinned    = 1 << 3;    // 0000 1000 (закріплений)
    const uint8_t Encrypted = 1 << 4;    // 0001 0000 (зашифрований)
}

namespace TextFlags { // прапори для обробки тексту
    const uint8_t None      = 0;
    const uint8_t Small     = 1 << 0;    // < 2 КБ (текст повністю в RAM)
    const uint8_t Normal    = 1 << 1;    // 2 КБ - 16 КБ (хвіст на диску)
    const uint8_t File      = 1 << 2;    // > 16 КБ (хвіст в окремому файлі)
    const uint8_t Dynamic   = 1 << 3;    // сенситивні дані (лише RAM, не пишемо на диск)
}

#pragma pack(push, 8)
struct ClipEntry {
    // === метадані (8 байтів) ===
    uint32_t textLength; // 4 байти. довжина тексту в символах wchar_t
    uint8_t  dataflags;  // 1 байт. стан (Empty, Used, etc.)
    uint8_t  textflags;  // 1 байт. розмір/тип (Small, Normal, File, Dynamic)
    uint16_t reserved;   // 2 байти. резерв/падінг для вирівнювання

    // === корисне навантаження (2040 байтів = 1020 символів wchar_t) ===
    union {
        wchar_t text[1020]; // варіант А: текст до 1020 символів
        struct {
            wchar_t preview[988]; // варіант Б: прев'ю 988 символів
            wchar_t fileName[32]; // ім'я файлу на 32 символи, якщо TextFlags::File
        } fileData;
    };
};
#pragma pack(pop)

// гарантія правильної математики пам'яті (компілятор видасть помилку, якщо розмір не 2 КБ)
static_assert(sizeof(ClipEntry) == RAM_BLOCK_SIZE, "ClipEntry layout size miscalculation!");

// === глобальні масиви пам'яті (1 МБ сумарно у секції .bss) ===
ClipEntry unpinnedBuffer[256] = { 0 }; // основний масив
ClipEntry pinnedBuffer[256] = { 0 };   // масив для закріплених записів

// лічильники з автообертанням (автоматично переходять 255 -> 0)
uint8_t unpinnedHead = 255; // починаємо з 255, щоб перше додавання (++head) записало в 0
uint8_t pinnedHead = 255;
int firstPinnedListIdx = -1; // зберігає позицію першого закріпленого запису в UI для швидкого стрибка

HWND hMainWindow = NULL;              // головне вікно програми   
HWND hSettingsWindow = NULL;          // вікно налаштувань
HWND hListBox = NULL;                 // елемент переліку-історії UI

bool ignoreClipboardUpdate = false;   // запобіжник: якщо true, програма ігнорує копіювання (бо робить його сама)

// === бекапи та технічні змінні ===
wchar_t* g_SysClipboardBackup = NULL; // тимчасове сховище для справжнього буфера обміну ОС
WNDPROC OldListBoxProc;              // попередня функція обробки списку (для підміни кліків мишею)
int lastAltCIndex = -1;         // lastAltCIndex вказує на індекс у буфері
bool lastAltCIsPinned = false;  // чи закріплений цей запис
// wchar_t* lastCopy = NULL;         // найновіший скопійований текст не через Alt+C

HHOOK g_hKeyboardHook = NULL;         // змінна для "шпигуна" за клавіатурою (глобальний хук)
#define MSG_PROCESS_HOTKEY (WM_APP + 1) // кастомне повідомлення, виклик вікна комбінацією

// === кешована графіка (GDI Objects: кольори, шрифти) ===
HBRUSH g_brMainBg = NULL, g_brCardNormal = NULL, g_brCardSelected = NULL, g_brBtnNormal = NULL;
HPEN g_penCardNormal = NULL, g_penCardSelected = NULL, g_penBtnNormal = NULL;
HFONT g_hFont = NULL; 
int g_ScaledItemHeight = 90;

// =|=|= структури та переліки (enums) =|=|=
enum class TransformMode { 
    Layout = 0,         // зміна розкладки (Pause)
    Case = 1,           // регістр (Alt+Pause)
    StrikeSlanted = 2,  // скісне закреслення (Alt+Numpad /)
    StrikeStraight = 3  // пряме закреслення (Alt+Numpad -)
};

enum class HotkeyCmd { 
    Layout = 1, Copy = 2, Paste = 3, MenuDown = 4, Cut = 6, 
    Undo = 7, MenuUp = 8, Case = 9, SilentCopyAll = 10, 
    StrikeSlanted = 11, StrikeStraight = 12,  // команди для косметики тексту
    PinCopy = 13, PinCut = 14, PinPaste = 15, TogglePinCurrent = 16  // команди для роботи із закріпленими в буфері
};

// // =|=|= словники для зміни розкладки =|=|=
// wchar_t eng_to_ukr[65536]; 
// wchar_t ukr_to_eng[65536]; 

wchar_t eng_to_ukr[128] = { 0 };  // ASCII охоплює всі англійські літери та базову пунктуацію (0..127)
wchar_t ukr_to_eng[2048] = { 0 };  // масиву на 2048 елементів достатньо за умови бітхешу

// ініціюємо словник парами символів для перекладу англійська <-> українська
void InitMaps() {
    const wchar_t pairs[][2] = { 
        { L'`', L'\''}, { L'~', L'₴' }, { L'@', L'"' }, { L'#', L'№' },
        { L'$', L';' }, { L'^', L':' }, { L'&', L'?' },
        { L'q', L'й' }, { L'w', L'ц' }, { L'e', L'у' }, { L'r', L'к' }, { L't', L'е' },
        { L'y', L'н' }, { L'u', L'г' }, { L'i', L'ш' }, { L'o', L'щ' }, { L'p', L'з' },
        { L'[', L'х' }, { L']', L'ї' }, { L'\\', L'\\' },
        { L'a', L'ф' }, { L's', L'і' }, { L'd', L'в' }, { L'f', L'а' }, { L'g', L'п' },
        { L'h', L'р' }, { L'j', L'о' }, { L'k', L'л' }, { L'l', L'д' }, { L';', L'ж' }, { L'\'', L'є' },
        { L'z', L'я' }, { L'x', L'ч' }, { L'c', L'с' }, { L'v', L'м' }, { L'b', L'и' },
        { L'n', L'т' }, { L'm', L'ь' }, { L',', L'б' }, { L'.', L'ю' }, { L'/', L'.' },
        { L'Q', L'Й' }, { L'W', L'Ц' }, { L'E', L'У' }, { L'R', L'К' }, { L'T', L'Е' },
        { L'Y', L'Н' }, { L'U', L'Г' }, { L'I', L'Ш' }, { L'O', L'Щ' }, { L'P', L'З' },
        { L'{', L'Х' }, { L'}', L'Ї' }, { L'|', L'/' },
        { L'A', L'Ф' }, { L'S', L'І' }, { L'D', L'В' }, { L'F', L'А' }, { L'G', L'П' },
        { L'H', L'Р' }, { L'J', L'О' }, { L'K', L'Л' }, { L'L', L'Д' }, { L':', L'Ж' }, { L'"', L'Є' },
        { L'Z', L'Я' }, { L'X', L'Ч' }, { L'C', L'С' }, { L'V', L'М' }, { L'B', L'И' },
        { L'N', L'Т' }, { L'M', L'Ь' }, { L'<', L'Б' }, { L'>', L'Ю' }, { L'?', L',' }
    };
    int count = sizeof(pairs) / sizeof(pairs[0]); // рахуємо кількість пар, щоб знати, скільки елементів обробити
    for (int i = 0; i < count; ++i) {  // пробігаємо циклом по переліку
        wchar_t eng = pairs[i][0];
        wchar_t ukr = pairs[i][1];
        
        if (eng < 128) eng_to_ukr[eng] = ukr;

        ukr_to_eng[ukr & 2047] = eng;   // відмасковуємо молодші 11 біт для отримання індексу без колізій
    }
}

// =|=|= управління графікою =|=|=
void InitGraphics() {
    HDC hdc = GetDC(NULL);
    int dpiY = GetDeviceCaps(hdc, LOGPIXELSY);
    ReleaseDC(NULL, hdc);
    
    int fontSize = -MulDiv(13, dpiY, 96); 
    g_ScaledItemHeight = MulDiv(g_Config.itemHeight, dpiY, 96);  
    g_hFont = CreateFontW(fontSize, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 
                        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, 
                        DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

    // створюємо всі пензлі та контури один раз
    g_brMainBg = CreateSolidBrush(RGB(25, 25, 25));
    g_brCardNormal = CreateSolidBrush(RGB(45, 45, 45));
    g_brCardSelected = CreateSolidBrush(RGB(70, 70, 75));
    g_brBtnNormal = CreateSolidBrush(RGB(50, 50, 55));
    
    g_penCardNormal = CreatePen(PS_SOLID, 1, RGB(60, 60, 60));
    g_penCardSelected = CreatePen(PS_SOLID, 1, RGB(100, 100, 110));
    g_penBtnNormal = CreatePen(PS_SOLID, 1, RGB(80, 80, 85));
}

void CleanupGraphics() {
    DeleteObject(g_brMainBg); DeleteObject(g_brCardNormal); DeleteObject(g_brCardSelected); DeleteObject(g_brBtnNormal);
    DeleteObject(g_penCardNormal); DeleteObject(g_penCardSelected); DeleteObject(g_penBtnNormal);
    DeleteObject(g_hFont);
}

void ApplyWindowShape(HWND hwnd) {
    HRGN hRgn = CreateRoundRectRgn(0, 0, g_Config.winWidth, g_Config.winHeight, g_Config.cornerRadius, g_Config.cornerRadius);
    SetWindowRgn(hwnd, hRgn, TRUE);
}

// =|=|= шифрування та файли =|=|=
// портативне CNG-шифрування (AES-256-CFB + SHA-256 Key Derivation) захищає збережені тексти на диску
void SecureProcessBuffer(BYTE* buffer, ULONG size, DWORD salt, bool isEncrypt) {
    if (size == 0) return;  // якщо порожньо - нічого не робимо
    // оголошуємо змінні для криптографічних інтерфейсів windows (cng)
    BCRYPT_ALG_HANDLE hHashAlg = NULL, hAesAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BYTE key[32] = { 0 }; // 32 байти для AES-256

    // генерація ключа (SHA-256: password + сіль)
    if (NT_SUCCESS(BCryptOpenAlgorithmProvider(&hHashAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) {
        if (NT_SUCCESS(BCryptCreateHash(hHashAlg, &hHash, NULL, 0, NULL, 0, 0))) {
            
            BCryptHashData(hHash, (PUCHAR)USER_KEY, lstrlenW(USER_KEY) * sizeof(wchar_t), 0); // додаємо пароль до хешу
            BCryptHashData(hHash, (PUCHAR)&salt, sizeof(salt), 0);    // додаємо сіль (індекс комірки або час)
            
            BCryptFinishHash(hHash, key, sizeof(key), 0);   // отримуємо 32-байтний криптографічний ключ
            BCryptDestroyHash(hHash);   // закриваємо хеш-об'єкт
        }
        BCryptCloseAlgorithmProvider(hHashAlg, 0);
    }
    // шифрування/розшифрування (AES-256-CFB)
    if (NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) {
        
        // (!) використовуємо режим CFB. тому що він не змінює розмір даних (немає Padding'у)
        BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CFB, sizeof(BCRYPT_CHAIN_MODE_CFB), 0);

        if (NT_SUCCESS(BCryptGenerateSymmetricKey(hAesAlg, &hKey, NULL, 0, key, sizeof(key), 0))) {   // створюємо симетричний ключ                
            ULONG resultLen = 0;
            BYTE iv[16] = { 0 }; // для CFB потрібен вектор ініціалізації. ключ уже унікалізований сіллю, нульовий IV безпечний

            if (isEncrypt) {   // якщо isencrypt = true, шифруємо дані прямо в тому ж буфері (in-place)
                BCryptEncrypt(hKey, buffer, size, NULL, iv, sizeof(iv), buffer, size, &resultLen, 0);
            } else {       // якщо ні — розшифровуємо
                BCryptDecrypt(hKey, buffer, size, NULL, iv, sizeof(iv), buffer, size, &resultLen, 0);
            }
            BCryptDestroyKey(hKey);   // знищуємо ключ, щоб звільнити пам'ять
        }
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
    }
}

// =|=|= симуляція натискань =|=|=
// випереджаюче оголошення скасування фокусування меню після натискання Alt
void CancelWindowsMenuFocus();

// функція змушує систему думати, що ми натиснули комбінацію (напр. Ctrl+C)
void SendKeyCombo(WORD modifier, WORD key) {
    INPUT inputs[16] = {}; 
    int c = 0;
    
    // перевіряємо, чи фізично затиснуті клавіші користувачем
    bool lAltHeld = (GetAsyncKeyState(VK_LMENU) & 0x8000) != 0;
    bool lCtrlHeld = (GetAsyncKeyState(VK_LCONTROL) & 0x8000) != 0;
    bool rCtrlHeld = (GetAsyncKeyState(VK_RCONTROL) & 0x8000) != 0;
    bool lWinHeld = (GetAsyncKeyState(VK_LWIN) & 0x8000) != 0;  // перевірка лівого Win
    bool rWinHeld = (GetAsyncKeyState(VK_RWIN) & 0x8000) != 0;  // перевірка правого Win
    
    // якщо користувач тримає Alt або Win, відпускаємо їх програмно, щоб вони не псували Ctrl+C/V
    if (lAltHeld) { inputs[c].type = INPUT_KEYBOARD; inputs[c].ki.wVk = VK_LMENU; inputs[c].ki.dwFlags = KEYEVENTF_KEYUP; c++; }
    if (lWinHeld) { inputs[c].type = INPUT_KEYBOARD; inputs[c].ki.wVk = VK_LWIN; inputs[c].ki.dwFlags = KEYEVENTF_KEYUP; c++; }
    if (rWinHeld) { inputs[c].type = INPUT_KEYBOARD; inputs[c].ki.wVk = VK_RWIN; inputs[c].ki.dwFlags = KEYEVENTF_KEYUP; c++; }
    
    // натискаємо модифікатор (напр. Ctrl) і саму клавішу (напр. V), потім відпускаємо обох
    inputs[c].type = INPUT_KEYBOARD; inputs[c].ki.wVk = modifier; c++;
    inputs[c].type = INPUT_KEYBOARD; inputs[c].ki.wVk = key; c++;
    inputs[c].type = INPUT_KEYBOARD; inputs[c].ki.wVk = key; inputs[c].ki.dwFlags = KEYEVENTF_KEYUP; c++;
    inputs[c].type = INPUT_KEYBOARD; inputs[c].ki.wVk = modifier; inputs[c].ki.dwFlags = KEYEVENTF_KEYUP; c++;
    
    if (lAltHeld) { 
        inputs[c].type = INPUT_KEYBOARD; inputs[c].ki.wVk = VK_LMENU; c++;   // повертаємо лівий Alt, щоб користувач міг тримати його
        
        // обхід: клікаємо "пустим" Ctrl, щоб меню вікон (File, Edit...) не фокусувалося після відпускання Alt
        inputs[c].type = INPUT_KEYBOARD; inputs[c].ki.wVk = VK_LCONTROL; c++;
        inputs[c].type = INPUT_KEYBOARD; inputs[c].ki.wVk = VK_LCONTROL; inputs[c].ki.dwFlags = KEYEVENTF_KEYUP; c++;
    }
    if (lWinHeld) { inputs[c].type = INPUT_KEYBOARD; inputs[c].ki.wVk = VK_LWIN; c++; }
    if (rWinHeld) { inputs[c].type = INPUT_KEYBOARD; inputs[c].ki.wVk = VK_RWIN; c++; }

    // (!) якщо ми імітували відпускання Ctrl, але фізично він затиснутий, відновлюємо стан для ОС
    if (modifier == VK_CONTROL) {
        if (lCtrlHeld) { inputs[c].type = INPUT_KEYBOARD; inputs[c].ki.wVk = VK_LCONTROL; c++; }
        if (rCtrlHeld) { inputs[c].type = INPUT_KEYBOARD; inputs[c].ki.wVk = VK_RCONTROL; c++; }
    }
    
    SendInput(c, inputs, sizeof(INPUT)); 

    if (lAltHeld) {    // запобігаємо активації головного меню вікна (Файл, Правка і т.д.) через утримання Alt
        Sleep(10);
        CancelWindowsMenuFocus();
    }
}

// =|=|= допоміжні функції для роботи з диском =|=|=
// обчислює фізичний зсув (offset) блоку у файлі (індекс * 16 КБ)
LARGE_INTEGER CalculateOffset(uint8_t index, bool isPinned) {
    LARGE_INTEGER offset;
    // звичайні записи з 0, закріплені — після них (через 256 блоків)
    offset.QuadPart = (isPinned ? (256 * DISK_BLOCK_SIZE) : 0) + (static_cast<uint32_t>(index) * DISK_BLOCK_SIZE);
    return offset;
}

// =|=|= мапування для віртуального переліку =|=|=
struct VisualItem {
    uint8_t realIdx;
    uint8_t isPinned;
};
VisualItem g_VisualMap[512]; // зв'язок: індекс на екрані -> індекс у RAM
int g_VisualCount = 0;       // скільки всього карток зараз бачить користувач

void FormatPreviewForUI(const wchar_t* source, int sourceLen, wchar_t* dest); // випереджаюче оголошення для UpdateListBox

// оновлює список текстів у вікні UI, відображаючи тільки активні записи з урахуванням Pinned і Unpinned масивів
void UpdateListBox() {
    AcquireSRWLockShared(&g_DataLock); // блокуємо дані залишаючи доступ для читання
    SendMessage(hListBox, LB_RESETCONTENT, 0, 0); 
    wchar_t display[1024];  // максимальна довжина тексту для відображення
    wchar_t uiText[1024];
    g_VisualCount = 0;       // скидаємо лічильник видимих елементів перед перерахунком
    firstPinnedListIdx = -1; // скидаємо маркер початку закріплених записів перед перерахунком

    // // спершу виводимо звичайні (Unpinned) записи від найновішого до найстарішого
    // for (int i = 0; i < 256; i++) { // ітеруємо по буферу
    //     uint8_t realIdx = (unpinnedHead - i) & 255;
    //     ClipEntry& entry = unpinnedBuffer[realIdx];

    //     if (!(entry.dataflags & DataFlags::Used)) continue; // якщо комірка порожня/затомбстонена (кошик) — пропускаємо її
    //     FormatPreviewForUI(entry.text, entry.textLength, display);
    //     if (entry.textflags & TextFlags::Dynamic) {  // перевірка на блискавку
    //         StringCchPrintfW(uiText, ARRAYSIZE(uiText), L"⚡ %s", display);  // візуальний маркер для RAM-only текстів
    //     } else {
    //         StringCchCopyW(uiText, ARRAYSIZE(uiText), display);
    //     }
    //     LRESULT listItemIdx = SendMessageW(hListBox, LB_ADDSTRING, 0, (LPARAM)uiText);
    //     SendMessage(hListBox, LB_SETITEMDATA, listItemIdx, (0 << 8) | realIdx); // маска координати: 0 = Unpinned
    // }
    // for (int i = 255; i >= 0; i--) { // ітеруємо по буферу закріплені (Pinned) записи
    //     uint8_t realIdx = (pinnedHead - i) & 255;
    //     ClipEntry& entry = pinnedBuffer[realIdx];
        
    //     if (!(entry.dataflags & DataFlags::Used)) continue; // якщо комірка порожня або затомбстонена (кошик) — пропускаємо її
    //     FormatPreviewForUI(entry.text, entry.textLength, display);

    //     if (entry.textflags & TextFlags::Dynamic) {  // перевірка на блискавку і для запінених записів
    //         StringCchPrintfW(uiText, ARRAYSIZE(uiText), L"⚡ %s", display);
    //     } else {
    //         StringCchCopyW(uiText, ARRAYSIZE(uiText), display);
    //     }

    //     LRESULT listItemIdx = SendMessageW(hListBox, LB_ADDSTRING, 0, (LPARAM)uiText);
    //     SendMessage(hListBox, LB_SETITEMDATA, listItemIdx, (1 << 8) | realIdx); // маска координати: 1 = Pinned

    //     if (firstPinnedListIdx == -1) {  // запам'ятовуємо, де в переліку почався блок запінених
    //         firstPinnedListIdx = static_cast<int>(listItemIdx);
    //     }
    // }

    // мапуємо звичайні (Unpinned) записи від найновішого (unpinnedHead) до найстарішого
    for (int i = 0; i < 256; i++) {
        uint8_t realIdx = (unpinnedHead - i) & 255;    // вираховуємо реальний фізичний індекс у масиві
        
        if (unpinnedBuffer[realIdx].dataflags & DataFlags::Used) {    // комірка містить активні дані
            g_VisualMap[g_VisualCount++] = { realIdx, 0 };      // записуємо відповідність unpinnedBuffer[realIdx]
        }
    }

    // мапуємо закріплені (Pinned) запис у зворотному порядку (від старіших до новіших)
    for (int i = 255; i >= 0; i--) {
        uint8_t realIdx = (pinnedHead - i) & 255;     // вираховуємо реальний індекс у pinnedBuffer
        
        if (pinnedBuffer[realIdx].dataflags & DataFlags::Used) {     // запінена картка активна
            // запам'ятовуємо позицію першого запіненого елемента для стрибка Shift
            if (firstPinnedListIdx == -1) {
                firstPinnedListIdx = g_VisualCount;
            }
            g_VisualMap[g_VisualCount++] = { realIdx, 1 };    // записуємо відповідність pinnedBuffer[realIdx]
        }
    }
    
    ReleaseSRWLockShared(&g_DataLock); // знімаємо блокування даних

    SendMessage(hListBox, LB_SETCOUNT, g_VisualCount, 0);  // повідомляємо системі скільки всього рядків тепер в переліку
    InvalidateRect(hListBox, NULL, TRUE);    // кажемо Windows перемалювати список
}

// =|=|= управління історіює та видаленими записами =|=|=

// функція записує у сховище блок (метадані + текст) і за потреби хвіст або зовнішній файл
void SaveBlockToDisk(uint8_t index, bool isPinned, const wchar_t* fullText) {
    ClipEntry& entry = isPinned ? pinnedBuffer[index] : unpinnedBuffer[index]; // отримуємо посилання на комірку відразу при вході

    if (g_hDbFile != INVALID_HANDLE_VALUE) {   // використовуємо глобальний дескриптор. якщо файл чомусь закритий — виходимо
        DWORD written;
        if (!(entry.textflags & TextFlags::Dynamic)) {   // якщо це сенситивні дані, на диск не пишемо, лише оновлюємо лічильники, щоб не зламати номери комірок // Problem: старий запис йде на друге коло

            LARGE_INTEGER offset = CalculateOffset(index, isPinned); // стрибаємо до потрібного блоку
            SetFilePointerEx(g_hDbFile, offset, NULL, FILE_BEGIN);
       
            ClipEntry diskEntry = entry;  // створюємо копію даних для шифрування
            DWORD slotSalt = (isPinned ? 1000 : 0) + index;
            SecureProcessBuffer((BYTE*)&diskEntry, RAM_BLOCK_SIZE, slotSalt, true);  // шифруємо копію структури метаданих перед записом
            WriteFile(g_hDbFile, &diskEntry, RAM_BLOCK_SIZE, &written, NULL);    // записуємо 2 КБ (метадані + прев'ю)

            // якщо це Normal, дописуємо хвіст суворо в межах цього ж 16 КБ слота
            if (fullText && (entry.textflags & TextFlags::Normal) && entry.textLength > 1020) {
                DWORD tailBytes = (entry.textLength - 1020) * sizeof(wchar_t);
                BYTE* encTail = (BYTE*)HeapAlloc(GetProcessHeap(), 0, tailBytes); // тимчасово виділяємо пам'ять під хвіст
                if (encTail) {
                    memcpy(encTail, fullText + 1020, tailBytes);
                    SecureProcessBuffer(encTail, tailBytes, slotSalt, true); // шифрування хвоста на диску
                    WriteFile(g_hDbFile, encTail, tailBytes, &written, NULL); // дописуємо у файл за блоком метаданих
                    HeapFree(GetProcessHeap(), 0, encTail);
                }
            }
        }

        LARGE_INTEGER headsOffset;  // запис heads в кінець файлу
        headsOffset.QuadPart = 512 * DISK_BLOCK_SIZE; // стрибаємо в кінець
        SetFilePointerEx(g_hDbFile, headsOffset, NULL, FILE_BEGIN);
        
        uint8_t heads[2] = { unpinnedHead, pinnedHead };  // зберігаємо лічильники в кінці файлу
        WriteFile(g_hDbFile, heads, 2, &written, NULL); // записуємо 2 байти лічильників на зміщення
    }

    // якщо це великий текст, виносимо файл в окрему папку
    if (fullText && (entry.textflags & TextFlags::File) && !(entry.textflags & TextFlags::Dynamic)) {
        wchar_t filepath[MAX_PATH];
        StringCchPrintfW(filepath, MAX_PATH, DB_FOLDER_PATH L"%s", entry.fileData.fileName);
        // створюємо новий окремий файл
        HANDLE hLargeFile = CreateFileW(filepath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hLargeFile != INVALID_HANDLE_VALUE) {
            DWORD fullBytes = entry.textLength * sizeof(wchar_t);
            BYTE* encBuffer = (BYTE*)HeapAlloc(GetProcessHeap(), 0, fullBytes);
            if (encBuffer) {
                memcpy(encBuffer, fullText, fullBytes);
                DWORD fileSalt = GetTickCount();  // генеруємо сіль
                SecureProcessBuffer(encBuffer, fullBytes, fileSalt, true);   // шифруємо весь файл
                DWORD written;
                WriteFile(hLargeFile, &fileSalt, sizeof(fileSalt), &written, NULL);  // зберігаємо сіль (4 байти) на початку файлу
                WriteFile(hLargeFile, encBuffer, fullBytes, &written, NULL);
                HeapFree(GetProcessHeap(), 0, encBuffer);   // звільняємо пам'ять
            }
            CloseHandle(hLargeFile);  // закриваємо файл
        }
    }
}

// внутрішня функція без блокування. викликається тільки коли g_DataLock вже захоплено
void RemoveByRealIndex_Internal(uint8_t index, bool isPinned) {
    ClipEntry& entry = isPinned ? pinnedBuffer[index] : unpinnedBuffer[index];
    if (!(entry.dataflags & DataFlags::Used)) {  // якщо запис уже порожній або затомбстонений — нічого не робимо
        return; 
    }

    if (entry.textflags & TextFlags::File) {    // якщо це великий текст — перейменовуємо його файл
        wchar_t oldPath[MAX_PATH], newPath[MAX_PATH], newFileName[32];
        StringCchPrintfW(newFileName, 32, L"del_%s", entry.fileData.fileName); // нове ім'я файлу з префіксом del_
        
        // збираємо повні шляхи до старого та нового файлів
        StringCchPrintfW(oldPath, MAX_PATH, DB_FOLDER_PATH L"%s", entry.fileData.fileName);
        StringCchPrintfW(newPath, MAX_PATH, DB_FOLDER_PATH L"%s", newFileName);

        if (MoveFileW(oldPath, newPath)) { // перейменовуємо файл у сховищі
            // оновлюємо ім'я в структурі, щоб не втратити зв'язок із файлом
            StringCchCopyW(entry.fileData.fileName, 32, newFileName);
        }
    }

    entry.dataflags &= ~DataFlags::Used; // знімаємо прапорець Used (Tombstone-маркер - картка в кошику)

    // запобіжник для вставки Alt+V (якщо видалили те, що щойно скопіювали)
    if (lastAltCIndex == index && lastAltCIsPinned == isPinned) {
        lastAltCIndex = -1;
    }
}

// функція видаляє картки - переміщує запис в кошик (Tombstoning) - за справжнім індексом буфера
void RemoveByRealIndex(uint8_t index, bool isPinned) {
    AcquireSRWLockExclusive(&g_DataLock); // блокуємо дані
    RemoveByRealIndex_Internal(index, isPinned);
    ReleaseSRWLockExclusive(&g_DataLock);  // знімаємо блокування даних

    SaveBlockToDisk(index, isPinned, NULL); // зберігаємо оновлену затомбстонену картку на диск
}

// =|=|= обробка закріплених записів =|=|=
// функція переносить запис між двома барабанами (звичайного і закріпленого)
void TogglePinState(uint8_t realIdx, bool currentlyPinned) {
    AcquireSRWLockExclusive(&g_DataLock); // блокуємо дані
    // визначаємо джерело (звідки беремо)
    ClipEntry& sourceEntry = currentlyPinned ? pinnedBuffer[realIdx] : unpinnedBuffer[realIdx];
    if (!(sourceEntry.dataflags & DataFlags::Used)) {
        ReleaseSRWLockExclusive(&g_DataLock); // відпускаємо лок перед виходом
        return;
    }

    uint8_t& targetHead = currentlyPinned ? unpinnedHead : pinnedHead; // і куди переносимо)
    ClipEntry* targetBuffer = currentlyPinned ? unpinnedBuffer : pinnedBuffer;

    targetHead++; // зсуваємо лічильник цільового барабану (авто-обертання 255 -> 0)
    uint8_t targetIdx = targetHead;
    ClipEntry& targetEntry = targetBuffer[targetIdx];

    // якщо в цільовій комірці з минулого кола лежить великий текст - файл, - видаляємо його зараз (!)
    if ((targetEntry.dataflags & DataFlags::Used) && (targetEntry.textflags & TextFlags::File)) {
        wchar_t filepath[MAX_PATH];
        StringCchPrintfW(filepath, MAX_PATH, DB_FOLDER_PATH L"%s", targetEntry.fileData.fileName);
        DeleteFileW(filepath);
    }

    targetEntry = sourceEntry; // копіюємо 2 КБ структури з оперативки в оперативку
    
    if (currentlyPinned) targetEntry.dataflags &= ~DataFlags::Pinned; // коригуємо прапорці статусу в новій комірці
    else targetEntry.dataflags |= DataFlags::Pinned;

    // оскільки хвіст Normal жорстко прив'язаний до індексу блоку на диску, його треба перекопіювати
    wchar_t* normalTail = NULL;
    DWORD tailBytes = 0;
    if ((sourceEntry.textflags & TextFlags::Normal) && sourceEntry.textLength > 1020) {
        tailBytes = (sourceEntry.textLength - 1020) * sizeof(wchar_t);
        normalTail = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, tailBytes);
        if (normalTail && g_hDbFile != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER sourceOffset = CalculateOffset(realIdx, currentlyPinned);
            sourceOffset.QuadPart += RAM_BLOCK_SIZE; // зсув на хвіст
            
            SetFilePointerEx(g_hDbFile, sourceOffset, NULL, FILE_BEGIN);
            DWORD br; ReadFile(g_hDbFile, normalTail, tailBytes, &br, NULL); // читаємо хвіст прямо в XOR-і
            DWORD sourceSalt = (currentlyPinned ? 1000 : 0) + realIdx;
            SecureProcessBuffer((BYTE*)normalTail, br, sourceSalt, false); // розшифровуємо зі старого слоту
        }
    }

    sourceEntry.dataflags = DataFlags::Empty; // позначаємо перенесений запис Empty в попередньому переліку

    // робимо локальні копії станів для безпечного запису на диск поза локом
    ClipEntry diskTargetEntry = targetEntry;
    ClipEntry diskSourceEntry = sourceEntry;
    uint8_t currentUnpinnedHead = unpinnedHead;
    uint8_t currentPinnedHead = pinnedHead;

    ReleaseSRWLockExclusive(&g_DataLock); // знімаємо блокування, тексти в RAM вже консистентні

    if (g_hDbFile != INVALID_HANDLE_VALUE) {   // безпечно синхронізуємо з диском (один вхід до файлу для чотирьох задач)
        DWORD written;
        // записуємо нову комірку (метадані + прев'ю)
        LARGE_INTEGER headsOffset;
        headsOffset.QuadPart = 512 * DISK_BLOCK_SIZE;
        SetFilePointerEx(g_hDbFile, headsOffset, NULL, FILE_BEGIN);
        uint8_t heads[2] = { unpinnedHead, pinnedHead };    // оновлюємо глобальні лічильники в суперблоці (офсет 0)
        WriteFile(g_hDbFile, heads, 2, &written, NULL);
        // записуємо зашифровані метадані в новий слот цільового барабану
        LARGE_INTEGER targetOffset = CalculateOffset(targetIdx, !currentlyPinned);
        SetFilePointerEx(g_hDbFile, targetOffset, NULL, FILE_BEGIN);
        DWORD targetSalt = (!currentlyPinned ? 1000 : 0) + targetIdx;
        SecureProcessBuffer((BYTE*)&diskTargetEntry, RAM_BLOCK_SIZE, targetSalt, true);
        WriteFile(g_hDbFile, &diskTargetEntry, RAM_BLOCK_SIZE, &written, NULL);

        if (normalTail) {   // якщо був хвіст Normal-тексту, записуємо його у новий офсет
            SecureProcessBuffer((BYTE*)normalTail, tailBytes, targetSalt, true);  // виклик шифрування хвоста
            WriteFile(g_hDbFile, normalTail, tailBytes, &written, NULL);   // запис
        }

        // позначаємо стару комірку на диску Empty
        LARGE_INTEGER sourceOffset = CalculateOffset(realIdx, currentlyPinned);
        SetFilePointerEx(g_hDbFile, sourceOffset, NULL, FILE_BEGIN);
        DWORD sourceSalt = (currentlyPinned ? 1000 : 0) + realIdx;
        SecureProcessBuffer((BYTE*)&diskSourceEntry, RAM_BLOCK_SIZE, sourceSalt, true);
        WriteFile(g_hDbFile, &diskSourceEntry, RAM_BLOCK_SIZE, &written, NULL);
    }
    if (normalTail) HeapFree(GetProcessHeap(), 0, normalTail);
}

// =|=|= глобальний хук клавіатури =|=|=
// хелпер-фікс для відміни фокусування меню після натискання Alt
void CancelWindowsMenuFocus() {
    INPUT in[2] = {};
    in[0].type = INPUT_KEYBOARD; in[0].ki.wVk = VK_CONTROL;
    in[1].type = INPUT_KEYBOARD; in[1].ki.wVk = VK_CONTROL; in[1].ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(2, in, sizeof(INPUT));
}

LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        KBDLLHOOKSTRUCT* pKeyBoard = (KBDLLHOOKSTRUCT*)lParam;
        if (pKeyBoard->flags & LLKHF_INJECTED) {   // ігноруємо синтетичні події (від нашого SendInput) для запобігання race conditions
            return CallNextHookEx(g_hKeyboardHook, nCode, wParam, lParam);
        }
        bool isKeyDown = (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN);
        bool isKeyUp = (wParam == WM_KEYUP || wParam == WM_SYSKEYUP);
        
        bool isLeftAltPressed = (GetAsyncKeyState(VK_LMENU) & 0x8000) != 0;  // читаємо стан клавіш-модифікаторів в обхід асинхронної черги повідомлень
        bool isRightAltPressed = (GetAsyncKeyState(VK_RMENU) & 0x8000) != 0;
        bool isCtrlPressed = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;

        // відстеження CTRL+A
        static bool ctrlA_handled = false;  // запобігає спаму повідомлень при утримуванні клавіші 'A'
        if (pKeyBoard->vkCode == 'A') {
            if (isKeyDown) {
                if (isCtrlPressed && !isLeftAltPressed && !isRightAltPressed) {
                    if (!ctrlA_handled) {
                        ctrlA_handled = true;   // сигналізуємо системі про натиснутий Ctrl+A
                        PostMessage(hMainWindow, MSG_PROCESS_HOTKEY, static_cast<WPARAM>(HotkeyCmd::SilentCopyAll), 0);
                    }
                }
            } else if (isKeyUp) {
                ctrlA_handled = false; 
            }
        }

        if (isKeyDown) {
            // перевіряємо комбінацію Alt+Win або Win+Alt при відкритому вікні
            if (IsWindowVisible(hMainWindow)) {
                bool isWin = (pKeyBoard->vkCode == VK_LWIN || pKeyBoard->vkCode == VK_RWIN);
                bool isAlt = (pKeyBoard->vkCode == VK_LMENU || pKeyBoard->vkCode == VK_RMENU);
                
                // якщо одна з них натиснута, а інша вже утримується фізично
                if ((isWin && ((GetAsyncKeyState(VK_LMENU) & 0x8000) || (GetAsyncKeyState(VK_RMENU) & 0x8000))) ||
                    (isAlt && ((GetAsyncKeyState(VK_LWIN) & 0x8000) || (GetAsyncKeyState(VK_RWIN) & 0x8000)))) 
                {
                    CancelWindowsMenuFocus();  // скидаємо фокус системного меню Windows (фікс для Alt)
                    // кидаємо асинхронне завдання процесу вікна і повертаємо керування ОС
                    PostMessage(hMainWindow, MSG_PROCESS_HOTKEY, static_cast<WPARAM>(HotkeyCmd::TogglePinCurrent), 0);
                    return 1; // блокуємо подію: Win/Alt не дійдуть до ОС
                }
            }
            if (pKeyBoard->vkCode == VK_PAUSE) {
                if (isRightAltPressed) return CallNextHookEx(g_hKeyboardHook, nCode, wParam, lParam);
                
                if (isLeftAltPressed) { 
                    CancelWindowsMenuFocus(); 
                    PostMessage(hMainWindow, MSG_PROCESS_HOTKEY, static_cast<WPARAM>(HotkeyCmd::Case), 0); 
                } 
                else PostMessage(hMainWindow, MSG_PROCESS_HOTKEY, static_cast<WPARAM>(HotkeyCmd::Layout), 0);                  
                return 1;
            }
            // перевіряємо, чи затиснута будь-яка з клавіш Windows
            bool isWinPressed = (GetAsyncKeyState(VK_LWIN) & 0x8000) != 0 || (GetAsyncKeyState(VK_RWIN) & 0x8000) != 0;
            // глобальні суперкомбінації (затиснуті Alt і Win)
            if (isLeftAltPressed && isWinPressed && !isRightAltPressed) {
                if (pKeyBoard->vkCode == 'C') { CancelWindowsMenuFocus(); PostMessage(hMainWindow, MSG_PROCESS_HOTKEY, static_cast<WPARAM>(HotkeyCmd::PinCopy), 0); return 1; }
                if (pKeyBoard->vkCode == 'X') { CancelWindowsMenuFocus(); PostMessage(hMainWindow, MSG_PROCESS_HOTKEY, static_cast<WPARAM>(HotkeyCmd::PinCut), 0); return 1; }
                if (pKeyBoard->vkCode == 'V') { CancelWindowsMenuFocus(); PostMessage(hMainWindow, MSG_PROCESS_HOTKEY, static_cast<WPARAM>(HotkeyCmd::PinPaste), 0); return 1; }
            }
            
            if (isLeftAltPressed && !isRightAltPressed && !isWinPressed) { 
                if (pKeyBoard->vkCode == 'C') { CancelWindowsMenuFocus(); PostMessage(hMainWindow, MSG_PROCESS_HOTKEY, static_cast<WPARAM>(HotkeyCmd::Copy), 0); return 1; }
                if (pKeyBoard->vkCode == 'V') { CancelWindowsMenuFocus(); PostMessage(hMainWindow, MSG_PROCESS_HOTKEY, static_cast<WPARAM>(HotkeyCmd::Paste), 0); return 1; }
                if (pKeyBoard->vkCode == 'B') { CancelWindowsMenuFocus(); PostMessage(hMainWindow, MSG_PROCESS_HOTKEY, static_cast<WPARAM>(HotkeyCmd::MenuDown), 0); return 1; }
                if (pKeyBoard->vkCode == 'X') { CancelWindowsMenuFocus(); PostMessage(hMainWindow, MSG_PROCESS_HOTKEY, static_cast<WPARAM>(HotkeyCmd::Cut), 0); return 1; } 
                if (pKeyBoard->vkCode == 'Z') { CancelWindowsMenuFocus(); PostMessage(hMainWindow, MSG_PROCESS_HOTKEY, static_cast<WPARAM>(HotkeyCmd::Undo), 0); return 1; } 
                if (pKeyBoard->vkCode == 'N') { CancelWindowsMenuFocus(); PostMessage(hMainWindow, MSG_PROCESS_HOTKEY, static_cast<WPARAM>(HotkeyCmd::MenuUp), 0); return 1; } 
                if (pKeyBoard->vkCode == 'Q') {  // вихід з програми (Alt+Q)
                    CancelWindowsMenuFocus(); 
                    PostMessage(hMainWindow, WM_CLOSE, 0, 0); 
                    return 1; 
                }
                if (pKeyBoard->vkCode == VK_DIVIDE) { 
                    CancelWindowsMenuFocus();
                    PostMessage(hMainWindow, MSG_PROCESS_HOTKEY, static_cast<WPARAM>(HotkeyCmd::StrikeSlanted), 0); 
                    return 1; 
                } 
                if (pKeyBoard->vkCode == VK_SUBTRACT) { 
                    CancelWindowsMenuFocus();
                    PostMessage(hMainWindow, MSG_PROCESS_HOTKEY, static_cast<WPARAM>(HotkeyCmd::StrikeStraight), 0); 
                    return 1; 
                }
            }
        }
    }
    return CallNextHookEx(g_hKeyboardHook, nCode, wParam, lParam);
}

// =|=|= робота з файлами (для великих текстів) =|=|=

// функція генерує компактне ім'я для відокремлених файлів - понад 16 КБ - (формат: РРММДД_ГГХХСС_текст)
void GenerateLargeFileName(wchar_t* outName, const wchar_t* sourceText) {
    SYSTEMTIME st;
    GetLocalTime(&st); // отримуємо поточний локальний час системи
    
    // створюємо короткий префікс часу: РРММДД_ГГХХСС (st.wYear % 100 забирає лише останні 2 цифри року)
    wchar_t timeStr[16];
    StringCchPrintfW(timeStr, 16, L"%02d%02d%02d_%02d%02d%02d", st.wYear % 100, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    // витягаємо безпечні символи тексту (до 17 символів)
    wchar_t cleanText[18] = {0}; // 17 символів + нуль
    int j = 0;
    for (int i = 0; sourceText[i] != L'\0' && j < 17; i++) { // біжимо по тексту, поки не наберемо 17 чистих чарів
        wchar_t c = sourceText[i];
        if (c == L'\r' || c == L'\n' || c == L'\t' || c == L' ') { // замінюємо всі переноси, табуляції та пробіли на підкреслення
            if (j > 0 && cleanText[j-1] != L'_') cleanText[j++] = L'_';
            continue;
        }
        if (wcschr(L"\\/:*?\"<>|.", c) == NULL) { // якщо символ не заборонений файловою системою Windows і не крапка (.), щоб уникнути імітації розширень
            cleanText[j++] = c; // копіюємо його в ім'я файлу
        }
    }
    if (j > 0 && cleanText[j-1] == L'_') cleanText[j-1] = L'\0'; // прибираємо підкреслення наприкінці, якщо воно там залишилось

    // збираємо фінальне ім'я у буфер картки (максимум 31 символ + нуль-термінатор)
    if (j > 0) {
        StringCchPrintfW(outName, 32, L"%s_%s", timeStr, cleanText); // якщо текст наявний: 260524_235959_MyText
    } else {
        StringCchPrintfW(outName, 32, L"%s_file", timeStr); // якщо тексту немає взагалі: 260524_235959_file
    }
}

// додаємо новий запис в історію в кільцевий буфер RAM
void AddToHistory(const wchar_t* text, uint16_t extraDataFlags = 0, uint16_t extraTextFlags = 0) {
    if (!text) return;
    uint32_t len = lstrlenW(text);
    if (len == 0) return; // вихід, якщо новий "текст" порожній

    AcquireSRWLockExclusive(&g_DataLock); // блокуємо доступ до даних

    // дедуплікація: ігноруємо текст, якщо він ідентичний попередньому
    ClipEntry& lastEntry = unpinnedBuffer[unpinnedHead];
    if ((lastEntry.dataflags & DataFlags::Used) && lastEntry.textLength == len) {
        int checkLen = (len < 1020) ? len : 1020;  // порівнюємо всі 1020 символів
        if (wcsncmp(lastEntry.text, text, checkLen) == 0) {
            ReleaseSRWLockExclusive(&g_DataLock); // звільняємо дані перед виходом
            return;
        } 
    }

    unpinnedHead++;     // зсуваємо голову буфера (автообертання 255 -> 0 працює апаратно)
    ClipEntry& entry = unpinnedBuffer[unpinnedHead];

    if (entry.dataflags & DataFlags::Used) {   // якщо в комірці був старий запис (File) — чистимо його у сховищі
        RemoveByRealIndex_Internal(unpinnedHead, false);
    }

    if (extraTextFlags & TextFlags::Dynamic) {   // безпечна обробка TextFlags::Dynamic
        if (len > 1020) { 
            entry.dataflags = DataFlags::Empty;  // маркуємо комірку порожньою, бо текст завеликий
            ReleaseSRWLockExclusive(&g_DataLock);   // розблоковуємо дані перед виходом, щоб уникнути дедлоку
            return; 
        }
        entry.textLength = len;
        entry.dataflags = DataFlags::Used | extraDataFlags;
        entry.textflags = TextFlags::Dynamic; 
        wmemcpy(entry.text, text, len);

        ReleaseSRWLockExclusive(&g_DataLock);   // розблоковуємо дані перед дисковим I/O

        SaveBlockToDisk(unpinnedHead, false, text);    // записуємо лише оновлені лічильники heads на диск, без тексту
        return;
    }

    // заповнюємо 8 байтів нових метаданих
    entry.textLength = len;
    entry.dataflags = DataFlags::Used | extraDataFlags;
    entry.textflags = TextFlags::None | extraTextFlags;

    // сортування за розміром (межа 16 КБ в байтах після врахування голови = 8188 символи wchar_t)
    if (len <= 1020) {
        entry.textflags |= TextFlags::Small;
        wmemcpy(entry.text, text, len);  // копіюємо рівно len символів
    } 
    else if (len <= 8188) { 
        entry.textflags |= TextFlags::Normal;
        wmemcpy(entry.text, text, 1020); // копіюємо перші 1020 символів як inline-прев'ю (затре reserved поля на диску, що безпечно)
    } 
    else {
        entry.textflags |= TextFlags::File;
        wmemcpy(entry.fileData.preview, text, 988);
        GenerateLargeFileName(entry.fileData.fileName, text);   // створюємо назву файлу
        CreateDirectoryW(DB_FOLDER_NAME, NULL);
    }

    ReleaseSRWLockExclusive(&g_DataLock);  // звільняємо дані перед роботою з диском

    SaveBlockToDisk(unpinnedHead, false, text);    // синхронізуємо стан з диском
}

// функція відновлює індексну карту прев'ю після перезапуску
void LoadHistory() {
    g_hDbFile = CreateFileW(DB_FILE_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_hDbFile != INVALID_HANDLE_VALUE) {

        if (GetLastError() != ERROR_ALREADY_EXISTS) {   // попереднє виділення місця (Pre-allocation), якщо файл щойно створено
            LARGE_INTEGER fileSize;
            fileSize.QuadPart = (512 * DISK_BLOCK_SIZE) + 2;   // 512 блоків по 16 КБ + 2 байти для лічильників (heads) у самому кінці
            SetFilePointerEx(g_hDbFile, fileSize, NULL, FILE_BEGIN);

            LARGE_INTEGER headsOffset;
            headsOffset.QuadPart = 512 * DISK_BLOCK_SIZE;
            SetFilePointerEx(g_hDbFile, headsOffset, NULL, FILE_BEGIN);
            uint8_t initHeads[2] = { 255, 255 };    // відразу записуємо чисті лічильники в кінець файлу
            DWORD written;
            WriteFile(g_hDbFile, initHeads, 2, &written, NULL);
        }
        
        DWORD read;
        uint8_t heads[2] = { 255, 255 };

        LARGE_INTEGER headsOffset;   // читання лічильників з кінця файлу
        headsOffset.QuadPart = 512 * DISK_BLOCK_SIZE; // стрибаємо повз усі 512 блоків
        SetFilePointerEx(g_hDbFile, headsOffset, NULL, FILE_BEGIN);
        
        // читаємо і відновлюємо глобальні лічильники кільцевого буфера
        if (ReadFile(g_hDbFile, heads, 2, &read, NULL) && read == 2) {
            unpinnedHead = heads[0];
            pinnedHead = heads[1];
        }

        for (int i = 0; i < 256; i++) {     // завантажуємо індексні картки (по 2 КБ) для звичайних записів
            LARGE_INTEGER offset = CalculateOffset(i, false);
            SetFilePointerEx(g_hDbFile, offset, NULL, FILE_BEGIN);
            ClipEntry tempEntry; // тимчасова структура
            ReadFile(g_hDbFile, &tempEntry, RAM_BLOCK_SIZE, &read, NULL);
            if (read == RAM_BLOCK_SIZE) {
                if (tempEntry.dataflags == 0 && tempEntry.textLength == 0) continue;   // пропускаємо порожні блоки
                DWORD slotSalt = i;   // сіль — це індекс запису
                SecureProcessBuffer((BYTE*)&tempEntry, RAM_BLOCK_SIZE, slotSalt, false);  // спершу розшифровуємо
                if (tempEntry.dataflags & DataFlags::Used) {       // тепер безпечно перевіряємо прапорець
                    unpinnedBuffer[i] = tempEntry; // записуємо валідну картку в RAM
                }
            }
        }
        for (int i = 0; i < 256; i++) {  // також індексні картки (по 2 КБ) для закріплених записів
            LARGE_INTEGER offset = CalculateOffset(i, true);
            SetFilePointerEx(g_hDbFile, offset, NULL, FILE_BEGIN);
            ClipEntry tempEntry; 
            ReadFile(g_hDbFile, &tempEntry, RAM_BLOCK_SIZE, &read, NULL);
            if (read == RAM_BLOCK_SIZE) {
                if (tempEntry.dataflags == 0 && tempEntry.textLength == 0) continue;   // пропускаємо порожні блоки
                DWORD slotSalt = 1000 + i;  // сіль для isPinned
                SecureProcessBuffer((BYTE*)&tempEntry, RAM_BLOCK_SIZE, slotSalt, false);  // спершу розшифровуємо
                if (tempEntry.dataflags & DataFlags::Used) {
                    pinnedBuffer[i] = tempEntry; // записуємо валідну картку
                }
            }
        }    // не закриваємо файл, g_hDbFile продовжує працювати
    }
}

// логіка ледачого завантаження (Lazy Loading), читаємо повний запис у виділену пам'ять (викликається перед Ctrl+V)
wchar_t* LoadTextByRealIndex(uint8_t index, bool isPinned) {
    AcquireSRWLockExclusive(&g_DataLock); // блокуємо дані на час читання метаданих
    ClipEntry& entry = isPinned ? pinnedBuffer[index] : unpinnedBuffer[index];
    if (!(entry.dataflags & DataFlags::Used)) {
        ReleaseSRWLockExclusive(&g_DataLock);
        return NULL;
    }

    // динамічно просимо пам'ять у системи суворо під розмір тексту (+1 для нуль-термінатора рядка)
    wchar_t* targetBuffer = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, (entry.textLength + 1) * sizeof(wchar_t));
    if (!targetBuffer) {
        ReleaseSRWLockExclusive(&g_DataLock);
        return NULL;
    }

    ClipEntry localEntry = entry;  // робимо локальну копію структури та виділяємо необхідні дані
    ReleaseSRWLockExclusive(&g_DataLock); // відразу відпускаємо, далі працюємо з локальною копією

    if (localEntry.textflags & TextFlags::Dynamic) {     // обробка гілки TextFlags::Dynamic
        memcpy(targetBuffer, localEntry.text, localEntry.textLength * sizeof(wchar_t));   // в inline-буфері RAM
    }
    else if (localEntry.textflags & TextFlags::Small) {      // текст повністю лежить в RAM
        memcpy(targetBuffer, localEntry.text, localEntry.textLength * sizeof(wchar_t));
    } 
    else if (localEntry.textflags & TextFlags::Normal) {
        memcpy(targetBuffer, localEntry.text, 1020 * sizeof(wchar_t));   // варіант Б: Забираємо inline-частину (перші 1020 символів) з RAM
            
        if (g_hDbFile != INVALID_HANDLE_VALUE) {    // використовуємо глобальний дескриптор для дочитування хвоста
            LARGE_INTEGER offset = CalculateOffset(index, isPinned);
            offset.QuadPart += RAM_BLOCK_SIZE;  // стрибаємо повз 2 КБ картки прев'ю на початок хвоста
            SetFilePointerEx(g_hDbFile, offset, NULL, FILE_BEGIN);
            
            DWORD bytesToRead = (localEntry.textLength - 1020) * sizeof(wchar_t);
            DWORD bytesRead;
            ReadFile(g_hDbFile, targetBuffer + 1020, bytesToRead, &bytesRead, NULL);
            DWORD slotSalt = (isPinned ? 1000 : 0) + index;
            SecureProcessBuffer((BYTE*)(targetBuffer + 1020), bytesRead, slotSalt, false);  // знімаємо обфускацію з хвоста
        }
    } 
    else if (localEntry.textflags & TextFlags::File) {
        // варіант В: текст великий, читаємо його з окремого зовнішнього файлу
        wchar_t filepath[MAX_PATH];
        StringCchPrintfW(filepath, MAX_PATH, DB_FOLDER_PATH L"%s", localEntry.fileData.fileName);
        HANDLE hFile = CreateFileW(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD fileSalt = 0;
            DWORD bytesRead = 0;
            ReadFile(hFile, &fileSalt, sizeof(fileSalt), &bytesRead, NULL);   // читаємо унікальну сіль файлу (перші 4 байти)
            DWORD bytesToRead = localEntry.textLength * sizeof(wchar_t);
            ReadFile(hFile, targetBuffer, bytesToRead, &bytesRead, NULL);
            SecureProcessBuffer((BYTE*)targetBuffer, bytesRead, fileSalt, false);  // розшифровуємо все тіло файлу
            CloseHandle(hFile);
        } else {
            StringCchCopyW(targetBuffer, localEntry.textLength + 1, L"[ПОМИЛКА] Зовнішній файл не знайдено.");
        }
    }

    targetBuffer[localEntry.textLength] = L'\0'; // ставимо фінальний маркер кінця рядка
    return targetBuffer;
}



// =|=|= сепарація системного буфера і кастомного =|=|=
// бекап справжнього буфера обміну, щоб технічні копіювання (Ctrl+C) не знищили дані користувача
void BackupSysClipboard() {
    if (g_SysClipboardBackup) { HeapFree(GetProcessHeap(), 0, g_SysClipboardBackup); g_SysClipboardBackup = NULL; }  // про всяк скидаємо старий бекап
    if (OpenClipboard(NULL)) {  // відкриваємо системний буфер обміну (NULL - прив'язка до поточного потоку)
        HANDLE hData = GetClipboardData(CF_UNICODETEXT);
        if (hData) {  // якщо буфер не порожній і містить саме текст
            wchar_t* pText = static_cast<wchar_t*>(GlobalLock(hData));  // блокуємо мобільний блок пам'яті
            if (pText) {  // перевіряємо вказівник
                size_t cch = lstrlenW(pText) + 1; // рахуємо символи
                g_SysClipboardBackup = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, cch * sizeof(wchar_t));  // виділяємо пам'ять
                if (g_SysClipboardBackup) StringCchCopyW(g_SysClipboardBackup, cch, pText);  // копіюємо текст в локальну змінну
                GlobalUnlock(hData);  // знімаємо блокування
            }
        }
        CloseClipboard();  // закриваємо сесію
    }
}
// відновлюємо системний буфер обміну після роботи
void RestoreSysClipboard() {
    if (OpenClipboard(NULL)) {  // відкриваємо системний буфер
        if (!EmptyClipboard()) {  // очищуємо його (тепер наше вікно власник буфера)
            CloseClipboard();
            return;  // але якщо ОС не дозволила очистити буфер, негайно виходимо без видалення бекапу
        }
        if (g_SysClipboardBackup) {
            size_t bytes = (lstrlenW(g_SysClipboardBackup) + 1) * sizeof(wchar_t); // обчислюємо розмір бекапу
            HGLOBAL hData = GlobalAlloc(GMEM_MOVEABLE, bytes);  // для системи пам'ять буфера має бути виділена GlobalAlloc
            if (hData) {
                wchar_t* pDest = static_cast<wchar_t*>(GlobalLock(hData));
                StringCchCopyW(pDest, bytes / sizeof(wchar_t), g_SysClipboardBackup);  // записуємо збережений раніше буфер
                GlobalUnlock(hData);  // знімаємо блокування
                SetClipboardData(CF_UNICODETEXT, hData);
            }
        }
        CloseClipboard();  // закриваємо сесію
    } // віддали текст системі, локальний бекап більше не потрібен, очищуємо
    if (g_SysClipboardBackup) { HeapFree(GetProcessHeap(), 0, g_SysClipboardBackup); g_SysClipboardBackup = NULL; }
}
// очищує чергу повідомлень ОС, щоб утиліта не реагувала на свої ж копіювання
void ClearPendingClipboardUpdates() {
    MSG msg;
    while (PeekMessage(&msg, hMainWindow, WM_CLIPBOARDUPDATE, WM_CLIPBOARDUPDATE, PM_REMOVE)) {}
}

// кастомне копіювання/вирізання (наприклад, через Alt+C). 
// setAsAltC вказує, чи потрібно запам'ятати цей текст для швидкої вставки через Alt+V
void CustomCopyOrCut(WORD vkCode, bool setAsAltC = true, bool copyDirectToPinned = false) { 
    ignoreClipboardUpdate = true; // кажемо обробнику ігнорувати наступну зміну буфера
    BackupSysClipboard();
    
    DWORD startSeq = GetClipboardSequenceNumber();
    SendKeyCombo(VK_CONTROL, vkCode); // імітуємо Ctrl+C або Ctrl+X
    
    bool updated = false;
    for (int i = 0; i < 16; ++i) { // чекаємо, поки програма-донор віддасть текст у буфер обміну
        Sleep(20);
        if (GetClipboardSequenceNumber() != startSeq) { updated = true; break; }
    }
    Sleep(30); 
    
    if (updated && OpenClipboard(NULL)) {
        HANDLE hData = GetClipboardData(CF_UNICODETEXT);
        if (hData) {
            wchar_t* pText = static_cast<wchar_t*>(GlobalLock(hData));
            if (pText) {
                AcquireSRWLockExclusive(&g_DataLock); // блокуванням даних захищаємо роботу з глобальною пам'яттю

                if (copyDirectToPinned) {
                    pinnedHead++; // тимчасово зсуваємо pinnedHead вперед і робимо запис через проміжну змінну
                    ClipEntry& entry = pinnedBuffer[pinnedHead];
                    if (entry.dataflags & DataFlags::Used) {
                        RemoveByRealIndex_Internal(pinnedHead, true);
                    }
                    uint32_t len = lstrlenW(pText);
                    entry.textLength = len;
                    entry.dataflags = DataFlags::Used | DataFlags::Pinned | (setAsAltC ? DataFlags::CtrlC : 0);
                    
                    if (len <= 1020) {
                        entry.textflags = TextFlags::Small;
                        wmemcpy(entry.text, pText, len);
                    } else if (len <= 8188) {
                        entry.textflags = TextFlags::Normal;
                        wmemcpy(entry.text, pText, 1020);  // копіюємо рівно 1020 символів
                    } else {
                        entry.textflags = TextFlags::File;
                        wmemcpy(entry.fileData.preview, pText, 988);
                        GenerateLargeFileName(entry.fileData.fileName, pText);
                        CreateDirectoryW(DB_FOLDER_NAME, NULL);
                    }
                    ReleaseSRWLockExclusive(&g_DataLock);   // звільняємо блокування перед тривалим записом на диск
                    SaveBlockToDisk(pinnedHead, true, pText);  // записуємо на диск
                    AcquireSRWLockExclusive(&g_DataLock); // знову блокуємо для збереження технічних індексів
                    
                    if (setAsAltC) {
                        lastAltCIndex = pinnedHead;  // запам'ятовуємо індекс закріпленої картки кільцевого буфера
                        lastAltCIsPinned = true;
                    }
                } else {
                    ReleaseSRWLockExclusive(&g_DataLock); // звільняємо, бо AddToHistory сама заблокує дані всередині
                    AddToHistory(pText, setAsAltC ? DataFlags::CtrlC : 0);  // зберігаємо текст в історію (він стане на позицію unpinnedHead)
                    AcquireSRWLockExclusive(&g_DataLock); // блокуємо знову для безпечного запису індексу Alt+V
                    if (setAsAltC) {
                        lastAltCIndex = unpinnedHead;  // запам'ятовуємо індекс картки кільцевого буфера для Alt+V
                        lastAltCIsPinned = false;
                    }
                }
                ReleaseSRWLockExclusive(&g_DataLock); // фінально відпускаємо захист даних
                GlobalUnlock(hData);
            }
        }
        CloseClipboard();
    }

    RestoreSysClipboard(); // відновлюємо початковий буфер
    ClearPendingClipboardUpdates();
    ignoreClipboardUpdate = false;
}

// вставка Alt+V останнього скопійованого через Alt+C тексту (або фолбек)
void PasteLastAltC() { 
    if (lastAltCIndex == -1) return; // нема AltC
    
    // ледаче завантаження тексту під потребу вставки
    wchar_t* textToPaste = LoadTextByRealIndex(static_cast<uint8_t>(lastAltCIndex), lastAltCIsPinned);
    if (!textToPaste) return;

    ignoreClipboardUpdate = true;
    BackupSysClipboard();  // бекапимо системний Ctrl+C

    if (textToPaste && OpenClipboard(NULL)) {
        if (!EmptyClipboard()) {  // якщо ОС відмовила в очищенні, скасовуємо, щоб не надіслати помилковий Ctrl+V
            CloseClipboard();
            goto cleanup; 
        }
        size_t cch = lstrlenW(textToPaste) + 1;
        HGLOBAL hData = GlobalAlloc(GMEM_MOVEABLE, cch * sizeof(wchar_t));
        if (hData) {
            wchar_t* pDest = static_cast<wchar_t*>(GlobalLock(hData));
            StringCchCopyW(pDest, cch, textToPaste);
            GlobalUnlock(hData);
            SetClipboardData(CF_UNICODETEXT, hData);
        }
        CloseClipboard();
        
        SendKeyCombo(VK_CONTROL, 0x56); // імітація натискання Ctrl+V
        Sleep(100); 
    }
cleanup:  // гарантована деініціалізація та відновлення стану хуків при будь-якому результаті транзакції
    if (textToPaste) HeapFree(GetProcessHeap(), 0, textToPaste); // чистимо оперативку після того, як ОС забрала текст
    RestoreSysClipboard();  // повертаємо стан системного буфера
    ClearPendingClipboardUpdates();  // чистимо чергу повідомлень ОС
    ignoreClipboardUpdate = false;  // повертаємо хук буфера
}
// вставка конкретного тексту з історії (вибір через віконце)
void PasteFromHistory(int index) {
    if (index < 0 || index >= g_VisualCount) return;  // перевіряємо, чи індекс у межах наявних у UI карток

    bool isPinned = g_VisualMap[index].isPinned; // дізнаємось, чи закріплена ця картка
    uint8_t realIdx = g_VisualMap[index].realIdx; // отримуємо її справжній індекс у кільцевому буфері
    
    if (!((GetAsyncKeyState(VK_LMENU) & 0x8000) || (GetAsyncKeyState(VK_RMENU) & 0x8000))) {
        ShowWindow(hMainWindow, SW_HIDE);   // ховаємо віконце лише якщо користувач не утримує клавішу Alt
    }
    ignoreClipboardUpdate = true; // запобігаємо самокопіюванню
    BackupSysClipboard();         // зберігаємо поточний буфер користувача

    wchar_t* textToPaste = LoadTextByRealIndex(realIdx, isPinned); // ледаче завантаження: дістаємо повний текст (з RAM, спільного або окремого файлу)
    if (textToPaste && OpenClipboard(NULL)) {
        if (!EmptyClipboard()) {
            CloseClipboard();
            goto cleanup; // стрибаємо до блоку очищення, щоб не виконати SendKeyCombo з Ctrl+V
        }
        size_t cch = lstrlenW(textToPaste) + 1;
        HGLOBAL hData = GlobalAlloc(GMEM_MOVEABLE, cch * sizeof(wchar_t));
        if (hData) {
            wchar_t* pDest = static_cast<wchar_t*>(GlobalLock(hData));
            StringCchCopyW(pDest, cch, textToPaste);
            GlobalUnlock(hData);
            SetClipboardData(CF_UNICODETEXT, hData); // передаємо текст у системний буфер обміну
        }
        CloseClipboard();
        
        SendKeyCombo(VK_CONTROL, 0x56); // імітуємо Ctrl+V для вставки тексту в активне вікно
        Sleep(100); // даємо системі час завершити вставку
    }
cleanup: // гарантоване відновлення стану програми та звільнення пам'яті
    RestoreSysClipboard();  // відновлюємо системний буфер
    ClearPendingClipboardUpdates();
    ignoreClipboardUpdate = false;

    // піднімаємо використаний текст нагору списку (якщо він не Pinned і далі перших 4-х елементів)
    if (textToPaste && !isPinned && realIdx != unpinnedHead && index >= 4) {
        RemoveByRealIndex(realIdx, false);
        AddToHistory(textToPaste);
    }
    if (textToPaste) HeapFree(GetProcessHeap(), 0, textToPaste);  // звільняємо пам'ять
}

// зміна розкладки, регістру або закреслення тексту прямо на льоту
void TransformClipboardText(TransformMode mode) {
    ignoreClipboardUpdate = true;  // блокуємо реакцію на зміну буфера, котру робимо
    BackupSysClipboard();  // зберігаємо оригінальний буфер

    DWORD currentSeq = GetClipboardSequenceNumber(); // беремо унікальний ID стану
    SendKeyCombo(VK_CONTROL, 0x43);   // надсилаємо системі натискання Ctrl+C
    
    bool clipboardUpdated = false;  // прапорець успішного перехоплення тексту
    for (int i = 0; i < 15; ++i) {  // циклічно чекаємо відповіді від програми-донора
        Sleep(20);
        if (GetClipboardSequenceNumber() != currentSeq) { clipboardUpdated = true; break; }  // ID змінився = текст надійшов
    }
    
    if (clipboardUpdated && OpenClipboard(NULL)) {  // буфер оновився і отримали доступ
        HANDLE hData = GetClipboardData(CF_UNICODETEXT);  // беремо дескриптор на Юнікод-текст
        if (hData) {
            wchar_t* pText = static_cast<wchar_t*>(GlobalLock(hData));  // фіксуємо пам'ять ОС та отримуємо рядок
            if (pText) {
                size_t len = lstrlenW(pText);  // обчислюємо довжину вхідного тексту
                size_t size = (mode == TransformMode::StrikeSlanted || mode == TransformMode::StrikeStraight) 
                              ? (len * 2 + 3) * sizeof(wchar_t)  // +3 символи для закреслення (ZWS + strike + нуль-термінатор)
                              : (len + 1) * sizeof(wchar_t);
                HGLOBAL hNewData = GlobalAlloc(GMEM_MOVEABLE, size);  // просимо в системи глобальний мобільний блок
                
                if (hNewData) {  // якщо ОС успішно виділила пам'ять
                    wchar_t* pNewText = static_cast<wchar_t*>(GlobalLock(hNewData));  // фіксуємо новий блок під запис
                    bool changed = false;  // перевіряємо, чи змінився хоч один символ

                    int toUkrCount = 0; // лічильник символів англ -> укр
                    int toEngCount = 0; // лічильник символів укр -> англ

                    if (mode == TransformMode::StrikeSlanted || mode == TransformMode::StrikeStraight) {      // закреслення тексту
                        wchar_t strikeChar = (mode == TransformMode::StrikeSlanted) ? L'\x0337' : L'\x0336';  // обираємо Юнікод-код скісної або прямої риски
                        size_t j = 0; // індекс для результуючого рядка
                        pNewText[j++] = L'\x200B'; // ставимо невидимий Zero-Width Space перед першою літерою
                        pNewText[j++] = strikeChar; // накладаємо на нього закреслення
                        for (size_t i = 0; i < len; ++i) { // йдемо по кожному символу оригіналу
                            pNewText[j++] = pText[i];
                            bool isHighSurrogate = (pText[i] >= 0xD800 && pText[i] <= 0xDBFF);  // перевіряємо, чи це не перша половина емодзі
                            if (!isHighSurrogate && pText[i] != L'\r' && pText[i] != L'\n' && pText[i] != L'\t') {  // ігноруємо службові переноси та сурогатні пари
                                pNewText[j++] = strikeChar;  // вклинюємо комбінований символ закреслення
                                changed = true; // успіх
                            }
                        }
                        pNewText[j] = L'\0';  // нуль-термінатор в кінці рядка
                    } 
                    else {   // зміна розкладки та регістру
                        bool lastWasEng = true;  // дефолним контекстом беремо англійську
                        for (size_t i = 0; i < len; ++i) {
                            wchar_t ch = pText[i];  // копіюємо кожен поточний символ
                            if (mode == TransformMode::Layout) {
                                wchar_t e = (ch < 128) ? eng_to_ukr[ch] : 0; // отримуємо переклади (для ASCII — з таблиці, інакше 0)
                                wchar_t u = ukr_to_eng[ch & 2047];

                                if (e && u) {  // символ присутній в обох таблицях (крапка, кома, апостроф тощо)
                                    if (lastWasEng) { pNewText[i] = e; toUkrCount++;}
                                    else { pNewText[i] = u; toEngCount++; }
                                    changed = true;
                                } else if (e) {  // однозначно англ -> укр
                                    pNewText[i] = e;
                                    lastWasEng = true;  // фіксуємо поточну мову слова як англійську
                                    changed = true;
                                    toUkrCount++;
                                } else if (u) {   // однозначно укр -> англ
                                    pNewText[i] = u;
                                    lastWasEng = false; // фіксуємо поточну мову слова як українську
                                    changed = true;
                                    toEngCount++;
                                } else { pNewText[i] = ch; } // цифри, пробіли
                            } else if (mode == TransformMode::Case) { // інверсія регістру
                                WCHAR c = ch;
                                if (IsCharUpperW(c)) { 
                                    CharLowerBuffW(&c, 1); // перетворення в нижній регістр
                                    pNewText[i] = c; 
                                    changed = true; 
                                }
                                else if (IsCharLowerW(c)) { 
                                    CharUpperBuffW(&c, 1);  // перетворення у верхній регістр
                                    pNewText[i] = c; 
                                    changed = true; 
                                }
                                else { pNewText[i] = ch; } // розділові знаки ігноруємо
                            }
                        }
                        pNewText[len] = L'\0'; // закриваємо Юнікод-рядок нулем
                    }

                    GlobalUnlock(hNewData);

                    if (changed) {   // якщо були зміни — вставляємо текст назад у програму
                        if (mode == TransformMode::Layout) { // якщо це була саме розкладка
                            HKL targetHKL = NULL; // дескриптор цільової мови
                            if (toUkrCount > toEngCount) { // якщо більшість символів стали українськими
                                targetHKL = LoadKeyboardLayoutW(L"00020422", KLF_ACTIVATE); // 0422 - код української розкладки
                            } else if (toEngCount > toUkrCount) { // якщо переважає англійська
                                targetHKL = LoadKeyboardLayoutW(L"00000409", KLF_ACTIVATE); // 0409 - код англійської розкладки США
                            }
                            if (targetHKL) { // якщо мова встановлена в системі
                                // просимо активне вікно змінити мову введення
                                PostMessage(GetForegroundWindow(), WM_INPUTLANGCHANGEREQUEST, 0, (LPARAM)targetHKL); 
                            }
                        }
                        if (!EmptyClipboard()) {  // очищуємо буфер обміну
                            GlobalFree(hNewData); // знищуємо новий рядок, бо ОС відмовилась його прийняти
                            GlobalUnlock(hData);  // розблоковуємо оригінальний буфер
                            CloseClipboard();     // закриваємо сесію
                            goto cleanup;         // і виходимо, щоб не натиснути Ctrl+V (SendKeyCombo)
                        }
                        SetClipboardData(CF_UNICODETEXT, hNewData);  // віддаємо ОС блок даних
                        GlobalUnlock(hData);  // розблоковуємо системний буфер обміну
                        CloseClipboard();  // закриваємо сесію Clipboard API

                        SendKeyCombo(VK_CONTROL, 0x56);  // імітуємо Ctrl+V тільки якщо буфер оновлено
                        Sleep(80); 
                        goto cleanup;   // стрибаємо на фінальне очищення
                    } else { GlobalFree(hNewData); }  // якщо змін не було — знищуємо виділену пам'ять
                }
            }
            GlobalUnlock(hData);  // знімаємо блок
        }
        CloseClipboard();
    }

cleanup:
    RestoreSysClipboard();  // повертаємо стан системного буфера
    ClearPendingClipboardUpdates();  // чистимо чергу повідомлень ОС
    ignoreClipboardUpdate = false;  // повертаємо хук буфера
}

// =|=|= інтерфейс та графіка =|=|=
// допоміжна функція: готує текст для відображення в меню, очищуючи його від переносів рядків (\n -> _)
void FormatPreviewForUI(const wchar_t* source, int sourceLen, wchar_t* dest) {
    int j = 0;
    for (int k = 0; k < sourceLen && j < g_Config.uiPreviewLength; k++) {  // обмеження циклу
        if (source[k] == L'\r') continue;   // ігноруємо переміщення курсора на початок поточного рядка 
        if (source[k] == L'\n') { dest[j++] = L' '; continue; }  // замінюємо переноси на пробіли
        dest[j++] = source[k];
        // ін'єкція невидимого пробілу (ZWS) для коректного перенесення довгих URL, шляхів та назв
        if (source[k] == L'/' || source[k] == L'=' || source[k] == L'&' || 
            source[k] == L'?' || source[k] == L'-' || source[k] == L'_') 
        {
            if (j < g_Config.uiPreviewLength) {
                dest[j++] = L'\x200B';
            }
        }
    }
    if (sourceLen > g_Config.uiPreviewLength && j <= g_Config.uiPreviewLength) {   // перевірка довжини
        StringCchCopyW(dest + j, 1024 - j, L"...\x2003\x2003\x2003\x2003");  // якщо текст більший ліміту — додаємо три крапки і місце для кнопок.
    } else {
        dest[j] = L'\0';
    }
}


// відображає вікно історії справа вгорі активного вікна
void ShowClipboardUI(bool selectLast = false, bool fromTray = false) {
    UpdateListBox();
    
    int count = SendMessage(hListBox, LB_GETCOUNT, 0, 0);
    if (count > 0) { SendMessage(hListBox, LB_SETCURSEL, selectLast ? count - 1 : 0, 0); }
    
    int x = 0, y = 0;
    
    RECT workArea;
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &workArea, 0); // отримуємо розмір екрану (без таскбару)

    if (fromTray) {    // якщо викликано з трею — показуємо завжди в правому верхньому кутку
        x = workArea.right - g_Config.winWidth - 20;
        y = workArea.top + 20;
    } else {    // намагаємось вивести вікно поруч з активним додатком, або на позиції курсору
        HWND hActive = GetForegroundWindow(); 
        RECT rect;
        if (hActive && GetWindowRect(hActive, &rect)) {
            x = rect.right - g_Config.winWidth - 20;
            y = rect.top + 20;
        } else {
            POINT pt; GetCursorPos(&pt); x = pt.x; y = pt.y;
        }
    }

    // запобіжник, щоб вікно ніколи не ховалося "за екран"
    if (x + g_Config.winWidth > workArea.right) x = workArea.right - g_Config.winWidth - 10;
    if (y + g_Config.winHeight > workArea.bottom) y = workArea.bottom - g_Config.winHeight - 10;
    if (x < workArea.left) x = workArea.left + 10;
    if (y < workArea.top) y = workArea.top + 10;

    SetWindowPos(hMainWindow, HWND_TOPMOST, x, y, g_Config.winWidth, g_Config.winHeight, SWP_SHOWWINDOW);
    SetForegroundWindow(hMainWindow);
    SetFocus(hListBox);
}

// колбек для перехоплення кліків мишею по списку (Listbox)
LRESULT CALLBACK ListBoxSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_MOUSEWHEEL) { // обробка скролінгу мишею
        int delta = GET_WHEEL_DELTA_WPARAM(wParam);
        int count = SendMessage(hwnd, LB_GETCOUNT, 0, 0);
        if (count > 0) {
            int curSel = SendMessage(hwnd, LB_GETCURSEL, 0, 0);
            if (delta < 0) {
                curSel = (curSel + 1) % count; // прокрутка вниз з переходом на початок
            } else {
                curSel = (curSel - 1 + count) % count; // прокрутка вгору з переходом у кінець
            }
            SendMessage(hwnd, LB_SETCURSEL, curSel, 0);
        }
        return 0; // перехоплюємо повідомлення, щоб перелік не скролився сам по собі
    }
    if (msg == WM_KEYDOWN && wParam == VK_SHIFT) {
        if ((lParam & 0x40000000) == 0 && firstPinnedListIdx != -1) {   // якщо натиснуто Shift ((lParam & 0x40000000) == 0 означає, що це перше натискання), стрибаємо на Pinned
            SendMessage(hwnd, LB_SETCURSEL, firstPinnedListIdx, 0);
            SendMessage(hwnd, LB_SETTOPINDEX, firstPinnedListIdx, 0);
        }
        // навмисне не робимо return 0, щоб система не "забула", що Alt утримується
    }
    if (msg == WM_RBUTTONDOWN) {
        DWORD itemInfo = SendMessage(hwnd, LB_ITEMFROMPOINT, 0, lParam);
        if (HIWORD(itemInfo) == 0) { 
            SendMessage(hwnd, LB_SETCURSEL, LOWORD(itemInfo), 0); // тільки виділяємо (щоб можна було видалити)
        }
        return 0; 
    }
    if (msg == WM_LBUTTONUP) {  // кнопку миші відпущено
        LRESULT res = CallWindowProc(OldListBoxProc, hwnd, msg, wParam, lParam);
        DWORD itemInfo = SendMessage(hwnd, LB_ITEMFROMPOINT, 0, lParam);
        if (HIWORD(itemInfo) == 0) {  // перевіряємо, чи клік саме по елементу тексту, а не по скролбару (повзунку)
            int selIdx = LOWORD(itemInfo);
            int clickX = GET_X_LPARAM(lParam);  // отримуємо горизонтальну координату кліку (X) з lParam
            int clickY = GET_Y_LPARAM(lParam);  // і вертикальну

            RECT itemRect;   // отримуємо фізичні координати цієї конкретної картки у списку
            SendMessage(hwnd, LB_GETITEMRECT, selIdx, (LPARAM)&itemRect);

            // вираховуємо розміщення кнопки так само, як ми її малювали
            int cardRight = itemRect.right - g_Config.itemGap;
            int cardBottom = itemRect.bottom - (g_Config.itemGap / 2);
            int btnRight = cardRight - 8;
            int btnLeft = btnRight - 38;
            int btnBottom = cardBottom - 8;
            int btnTop = btnBottom - 38;
            
            // якщо клік саме по кнопці "📌" (36x36 пікселів у кутку)
            if (clickX >= btnLeft && clickX <= btnRight && clickY >= btnTop && clickY <= btnBottom) {
                if (selIdx >= 0 && selIdx < g_VisualCount) {    // перевіряємо валідність виділеного елемента у віртуальній мапі
                    bool isPinned = g_VisualMap[selIdx].isPinned;    // читаємо метадані елемента з RAM-мапи
                    uint8_t realIdx = g_VisualMap[selIdx].realIdx;
                    
                    TogglePinState(realIdx, isPinned);   // змінюємо статус на протилежний
                    UpdateListBox();    // перераховуємо віртуальну мапу g_VisualMap та оновлюємо перелік
                    
                    int count = SendMessage(hwnd, LB_GETCOUNT, 0, 0);    // коригуємо виділення: якщо елемент зсунувся, тримаємо фокус на тій же позиції
                    if (count > 0) SendMessage(hwnd, LB_SETCURSEL, selIdx >= count ? count - 1 : selIdx, 0);
                }
                return 0; // перехоплюємо клік, не виконуємо стандартну вставку тексту
            }
            
            // клікнули по картці — виконуємо звичайну вставку тексту
            SendMessage(hwnd, LB_SETCURSEL, selIdx, 0);
            PostMessage(GetParent(hwnd), WM_COMMAND, MAKEWPARAM(1, 1000), (LPARAM)hwnd);  // вставляємо при лівому кліку
        }
        return 0;
    }
    return CallWindowProc(OldListBoxProc, hwnd, msg, wParam, lParam);
}

// функція для керування іконкою в системному лотку
void ManageTrayIcon(HWND hwnd, DWORD dwMessage) {
    NOTIFYICONDATAW nid = { sizeof(nid) };
    nid.hWnd = hwnd;
    nid.uID = 1;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    
    // намагаємось завантажити іконку з exe, якщо не знайдено — беремо стандартну
    nid.hIcon = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_APPICON));
    if (!nid.hIcon) nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    
    StringCchCopyW(nid.szTip, ARRAYSIZE(nid.szTip), L"Кастомний Буфер Обміну");
    Shell_NotifyIconW(dwMessage, &nid);
}
// =|=|= обробник вікна налаштувань (Settings Skeleton) =|=|=
LRESULT CALLBACK SettingsWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE:
            // Тут ти пізніше створиш UI елементи (кнопки, поля введення, повзунки)
            break;
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            FillRect(hdc, &ps.rcPaint, g_brMainBg);
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(200, 200, 200));
            SelectObject(hdc, g_hFont);
            RECT rc = {20, 20, 400, 100};
            DrawTextW(hdc, L"Вікно налаштувань (в розробці...)", -1, &rc, DT_LEFT | DT_TOP);
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_CLOSE:
            ShowWindow(hwnd, SW_HIDE); // лише ховаємо, не знищуємо
            return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

// =|=|= обробник головного вікна =|=|=
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE:  // cтворення вікна та елементів (меню, кнопки, список)  
            ManageTrayIcon(hwnd, NIM_ADD); // реєструємо іконку в треї при старті
            ApplyWindowShape(hwnd); // викликаємо лише тут (або якщо налаштування змінилися)

            hListBox = CreateWindowEx(0, L"LISTBOX", NULL, 
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY | LBS_WANTKEYBOARDINPUT | LBS_OWNERDRAWFIXED | LBS_NOINTEGRALHEIGHT | LBS_NODATA,
                0, g_Config.headerHeight, g_Config.winWidth, g_Config.winHeight - g_Config.headerHeight - g_Config.bottomHeight, hwnd, (HMENU)1, NULL, NULL);
            
            SendMessage(hListBox, WM_SETFONT, (WPARAM)g_hFont, TRUE);    // перелік повідомлень з кастомним виглядом
            SetWindowTheme(hListBox, L"Explorer", NULL);

            OldListBoxProc = (WNDPROC)SetWindowLongPtr(hListBox, GWLP_WNDPROC, (LONG_PTR)ListBoxSubclassProc);
            AddClipboardFormatListener(hwnd); // програма стає слухачем системного буфера обміну
            break;

        case WM_TRAYICON: // обробка кліків по іконці в треї
            if (lParam == WM_RBUTTONUP) {
                POINT pt; GetCursorPos(&pt);
                HMENU hMenu = CreatePopupMenu();     // створюємо меню трею
                AppendMenuW(hMenu, MF_STRING, 2, L"Налаштування");     // додавання пунктів меню
                AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
                AppendMenuW(hMenu, MF_STRING, 1, L"Вихід");
                
                SetForegroundWindow(hwnd); // фокус, щоб меню коректно закривалось при кліку повз
                int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, hwnd, NULL);
                DestroyMenu(hMenu);
                
                if (cmd == 1) SendMessage(hwnd, WM_CLOSE, 0, 0);
                else if (cmd == 2) {
                    // показуємо вікно налаштувань по центру екрану
                    SetWindowPos(hSettingsWindow, HWND_TOP, 0, 0, 400, 300, SWP_NOMOVE | SWP_SHOWWINDOW);
                }
            } else if (lParam == WM_LBUTTONUP) { // клік для відображення віконця
                ShowClipboardUI(false, true); // передаємо прапорець fromTray
            }
            break;

        case WM_NCHITTEST: { // дозволяємо тягати вікно за шапку і за нижню смужку
            LRESULT hit = DefWindowProc(hwnd, msg, wParam, lParam);
            if (hit == HTCLIENT) {
                POINT pt;
                pt.x = GET_X_LPARAM(lParam);
                pt.y = GET_Y_LPARAM(lParam);
                ScreenToClient(hwnd, &pt);
                
                if (pt.y < g_Config.headerHeight) {
                    if (pt.x >= g_Config.winWidth - g_Config.headerHeight) return HTCLIENT; 
                    return HTCAPTION; 
                }
                if (pt.y > g_Config.winHeight - g_Config.bottomHeight) {
                    return HTCAPTION; 
                }
            }
            return hit;
        }

        case WM_LBUTTONDOWN: { // клік по кнопці закриття "✕"
            POINT pt;
            pt.x = GET_X_LPARAM(lParam);
            pt.y = GET_Y_LPARAM(lParam);
            if (pt.y < g_Config.headerHeight && pt.x >= g_Config.winWidth - g_Config.headerHeight) {
                if (GetKeyState(VK_SHIFT) & 0x8000) {   // перевірка Shift для повного закриття, інакше тільки ховаємо віконце
                    SendMessage(hwnd, WM_CLOSE, 0, 0);
                } else {
                    ShowWindow(hwnd, SW_HIDE);
                }
            }
            break;
        }

        case WM_PAINT: { // малюємо кастомну шапку і футер
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(120, 120, 120));
            SelectObject(hdc, g_hFont);

            RECT rcHeader = {0, 0, g_Config.winWidth - g_Config.headerHeight, g_Config.headerHeight}; 
            DrawTextW(hdc, L"  ≡ Кастомний Буфер (Alt+Q — вихід)", -1, &rcHeader, DT_SINGLELINE | DT_VCENTER);

            RECT rcClose = {g_Config.winWidth - g_Config.headerHeight, 0, g_Config.winWidth, g_Config.headerHeight};
            SetTextColor(hdc, RGB(220, 110, 110)); 
            DrawTextW(hdc, L"✕", -1, &rcClose, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            RECT rcBottom = {0, g_Config.winHeight - g_Config.bottomHeight, g_Config.winWidth, g_Config.winHeight};
            SetTextColor(hdc, RGB(100, 100, 100));
            DrawTextW(hdc, L"  ≡ Shift + Клік на ✕ — повне закриття", -1, &rcBottom, DT_SINGLELINE | DT_VCENTER);

            EndPaint(hwnd, &ps);
            return 0;
        }

        case WM_CLIPBOARDUPDATE: { // перехоплюємо оновлення системного буфера (Ctrl+C)
            if (ignoreClipboardUpdate) break; // тимчасово блокуємо внутрішні копіювання

            if (OpenClipboard(hwnd)) {
                HANDLE hData = GetClipboardData(CF_UNICODETEXT);
                if (hData) {
                    wchar_t* pText = static_cast<wchar_t*>(GlobalLock(hData));
                    if (pText) {
                        AddToHistory(pText);  // додаємо системний текст до своєї історії
                        GlobalUnlock(hData);
                    }
                }
                CloseClipboard();
                
                int curSel = SendMessage(hListBox, LB_GETCURSEL, 0, 0);
                UpdateListBox();
                if (curSel != LB_ERR) SendMessage(hListBox, LB_SETCURSEL, curSel, 0);
            }
            break;
        }

        case WM_MEASUREITEM: { // визначаємо висоту одного запису списку
            MEASUREITEMSTRUCT* mis = (MEASUREITEMSTRUCT*)lParam;
            mis->itemHeight = g_ScaledItemHeight; 
            return TRUE;
        }
        
        case WM_DRAWITEM: { // gdi renderer одного запису (округлені картки)
            DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lParam;
            if (dis->itemID == -1 || dis->itemID >= (UINT)g_VisualCount) break;  // ігноруємо порожні запити або запити на індекси поза межами

            HDC hdc = dis->hDC;      // контекст малювання Windows (полотно)
            RECT rc = dis->rcItem;   // межі виділеного рядка на екрані
            bool isSelected = (dis->itemState & ODS_SELECTED); // відстежуємо виділений елемент

            RECT cardRect = rc;     // додаємо відступи всередині елемента
            cardRect.left += g_Config.itemGap; cardRect.right -= g_Config.itemGap;
            cardRect.top += g_Config.itemGap / 2; cardRect.bottom -= g_Config.itemGap / 2;

            // обираємо пензлі з пам'яті, залежно від того чи виділено елемент
            HGDIOBJ oldBrush = SelectObject(hdc, isSelected ? g_brCardSelected : g_brCardNormal);
            HGDIOBJ oldPen = SelectObject(hdc, isSelected ? g_penCardSelected : g_penCardNormal);
            // малювання RoundRect для фону картки
            RoundRect(hdc, cardRect.left, cardRect.top, cardRect.right, cardRect.bottom, g_Config.cornerRadius, g_Config.cornerRadius);

            VisualItem item = g_VisualMap[dis->itemID];   // дізнаємося, який саме елемент пам'яті відповідає рядку на екрані
            bool isPinned = item.isPinned;

            wchar_t display[1024];    // локальні буфери для тексту, щоб не тримати блокування пам'яті під час малювання
            wchar_t uiText[1024];

            AcquireSRWLockShared(&g_DataLock);    // shared-лок тільки для копіювання тексту
            ClipEntry& entry = isPinned ? pinnedBuffer[item.realIdx] : unpinnedBuffer[item.realIdx];   // отримуємо посилання на оригінальний запис в RAM
            
            // очищуємо текст від службових переносоів рядків і обрізаємо під розмір UI.
            const wchar_t* src = (entry.textflags & TextFlags::File) ? entry.fileData.preview : entry.text;
            int srcLen = (entry.textLength > 988) ? 988 : entry.textLength; // обмежуємо буфером прев'ю
            FormatPreviewForUI(src, srcLen, display);    // відформатований текст
            
            if (entry.textflags & TextFlags::Dynamic) {    // якщо це сенситивні дані (Dynamic), маркуємо блискавкою
                StringCchPrintfW(uiText, ARRAYSIZE(uiText), L"⚡ %s", display);
            } else {
                StringCchCopyW(uiText, ARRAYSIZE(uiText), display);
            }
            ReleaseSRWLockShared(&g_DataLock);    // відразу відпускаємо блокування

            SetBkMode(hdc, TRANSPARENT); // відмальовуємо текст без тла
            SetTextColor(hdc, RGB(240, 240, 240)); // майже білий колір тексту

            RECT textRect = cardRect;
            textRect.left += 14; textRect.right -= 14;  // відступ на початку і в кінці на 14
            textRect.top += 10; textRect.bottom -= 10;  // відступ згори 10
            DrawTextW(hdc, uiText, -1, &textRect, DT_WORDBREAK | DT_END_ELLIPSIS | DT_NOPREFIX);  // виводимо відформатований для картки текст

            RECT btnRect;  // малюємо кнопку піна (понад тексту, у правому нижньому кутку)
            btnRect.right = cardRect.right - 8;          // правий відступ від краю картки
            btnRect.left = btnRect.right - 38;            // ширина кнопки: 38px
            btnRect.bottom = cardRect.bottom - 8;        // відступ від низу картки
            btnRect.top = btnRect.bottom - 38;            // висота кнопки: 38px
            
            SelectObject(hdc, g_brBtnNormal);  // поле для кнопки
            SelectObject(hdc, g_penBtnNormal); // фон самої кнопки (яскравий, якщо закріплено)
            RoundRect(hdc, btnRect.left, btnRect.top, btnRect.right, btnRect.bottom, 16, 16);  // заокруглення кнопки 16
            
            SelectObject(hdc, oldBrush);    // відновлюємо старі об'єкти контексту, щоб не витікала пам'ять GDI
            SelectObject(hdc, oldPen);
            
            // якщо запис запінений — шпилька яскрава, якщо ні — тьмяна (підказка для кліку)
            SetTextColor(hdc, isPinned ? RGB(255, 120, 50) : RGB(80, 80, 85));
            DrawTextW(hdc, L"📌", -1, &btnRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            
            return TRUE;
        }

        case WM_TIMER: // таймер для неблокуючого виконання "Ctrl+A" копіювання
            if (wParam == 2026) {
                KillTimer(hwnd, 2026);
                CustomCopyOrCut(0x43, false);  // копіюємо (0x43 = 'C'), але не позначаємо як Alt+C (false), зберігаючи поточний Alt+V
            }
            break;

        case MSG_PROCESS_HOTKEY: { // обробка гарячих клавіш від хуку
            HotkeyCmd cmd = static_cast<HotkeyCmd>(wParam);
            
            if (cmd == HotkeyCmd::Layout) { TransformClipboardText(TransformMode::Layout); }  
            else if (cmd == HotkeyCmd::Copy) { CustomCopyOrCut(0x43, true); }    
            else if (cmd == HotkeyCmd::Cut) { CustomCopyOrCut(0x58, true); }  // вирізання
            else if (cmd == HotkeyCmd::Paste) {        // вставка з Alt+C
                if (IsWindowVisible(hMainWindow) && SendMessage(hListBox, LB_GETCURSEL, 0, 0) >= 0) {
                    PasteFromHistory(SendMessage(hListBox, LB_GETCURSEL, 0, 0));
                } else {   // вікно закрите або нічого не виділено
                    if (lastAltCIndex != -1) {
                        PasteLastAltC(); // якщо наявний запис від Alt+C
                    } else {   // якщо Alt+C немає, витягуємо найновіший запис через ListBox
                        UpdateListBox(); 
                        if (SendMessage(hListBox, LB_GETCOUNT, 0, 0) > 0) {
                            PasteFromHistory(0);
                        }
                    }
                }
            }
            // обробка комбінацій Alt+Win
            else if (cmd == HotkeyCmd::PinCopy) { CustomCopyOrCut(0x43, true, true); }
            else if (cmd == HotkeyCmd::PinCut) { CustomCopyOrCut(0x58, true, true); }
            else if (cmd == HotkeyCmd::PinPaste) {    // вставка останнього саме закріпленого запису (шукаємо останній Used у pinned буфері)
                if (pinnedBuffer[pinnedHead].dataflags & DataFlags::Used) {
                    ignoreClipboardUpdate = true;
                    BackupSysClipboard();
                    wchar_t* textToPaste = LoadTextByRealIndex(pinnedHead, true);
                    if (textToPaste && OpenClipboard(NULL)) {
                        if (EmptyClipboard()) {  // перевіряємо успішність очищення перед виділенням пам'яті
                            size_t cch = lstrlenW(textToPaste) + 1;
                            HGLOBAL hData = GlobalAlloc(GMEM_MOVEABLE, cch * sizeof(wchar_t));
                            if (hData) {
                                wchar_t* pDest = static_cast<wchar_t*>(GlobalLock(hData));
                                StringCchCopyW(pDest, cch, textToPaste);
                                GlobalUnlock(hData);
                                SetClipboardData(CF_UNICODETEXT, hData);
                            }
                            CloseClipboard();
                            SendKeyCombo(VK_CONTROL, 0x56);
                            Sleep(100);
                        } else {   // збій EmptyClipboard: від'єднуємося та оминаємо імітацію натискання Ctrl+V
                            CloseClipboard();
                        }
                    }  // блок гарантованого вивільнення ресурсів потоку
                    if (textToPaste) HeapFree(GetProcessHeap(), 0, textToPaste);
                    RestoreSysClipboard();
                    ClearPendingClipboardUpdates();
                    ignoreClipboardUpdate = false;
                }
            }
            else if (cmd == HotkeyCmd::TogglePinCurrent) {   // перемикання закріплення
                int sel = SendMessage(hListBox, LB_GETCURSEL, 0, 0); // запит індексу виділеного рядка
                if (sel >= 0 && sel < g_VisualCount) {
                    bool isPinned = g_VisualMap[sel].isPinned;  // у власному потоці читаємо RAM-мапу та оновлюємо дані
                    uint8_t realIdx = g_VisualMap[sel].realIdx;
                    
                    TogglePinState(realIdx, isPinned); // змінюємо статус закріплення
                    UpdateListBox();                   // оновлюємо інтерфейс
                    
                    int count = SendMessage(hListBox, LB_GETCOUNT, 0, 0);  // коригуємо виділення картки у списку
                    if (count > 0) SendMessage(hListBox, LB_SETCURSEL, sel >= count ? count - 1 : sel, 0); 
                }
            }
            else if (cmd == HotkeyCmd::MenuDown) {     
                if (IsWindowVisible(hMainWindow)) {
                    int count = SendMessage(hListBox, LB_GETCOUNT, 0, 0);
                    if (count > 0) {
                        int sel = SendMessage(hListBox, LB_GETCURSEL, 0, 0);
                        SendMessage(hListBox, LB_SETCURSEL, (sel + 1) % count, 0); 
                    }
                } else { ShowClipboardUI(false); } 
            }     
            else if (cmd == HotkeyCmd::Undo) { SendKeyCombo(VK_CONTROL, 0x5A); }  
            else if (cmd == HotkeyCmd::MenuUp) {                            
                if (IsWindowVisible(hMainWindow)) {
                    int count = SendMessage(hListBox, LB_GETCOUNT, 0, 0);
                    if (count > 0) {
                        int sel = SendMessage(hListBox, LB_GETCURSEL, 0, 0);
                        SendMessage(hListBox, LB_SETCURSEL, (sel - 1 + count) % count, 0); 
                    }
                } else { ShowClipboardUI(true); } 
            }
            else if (cmd == HotkeyCmd::Case) { TransformClipboardText(TransformMode::Case); }  
            else if (cmd == HotkeyCmd::SilentCopyAll) { SetTimer(hwnd, 2026, 200, NULL); }  // запускаємо таймер, щоб програма-донор встигла віддати Ctrl+A
            else if (cmd == HotkeyCmd::StrikeSlanted) { TransformClipboardText(TransformMode::StrikeSlanted); } 
            else if (cmd == HotkeyCmd::StrikeStraight) { TransformClipboardText(TransformMode::StrikeStraight); } 
            break;
        }

        case WM_CTLCOLORLISTBOX: { // фарбуємо фон Listbox
            HDC hdc = (HDC)wParam;
            SetBkColor(hdc, RGB(25, 25, 25));       
            SetTextColor(hdc, RGB(240, 240, 240));  
            return (LRESULT)g_brMainBg; // глобальний кешований пензель          
        }

        case WM_SIZE:  // якщо вікно змінює розмір - розтягуємо список
            MoveWindow(hListBox, 0, g_Config.headerHeight, LOWORD(lParam), HIWORD(lParam) - g_Config.headerHeight - g_Config.bottomHeight, TRUE);
            break;

        case WM_COMMAND: // клік по елементу списку
            if (LOWORD(wParam) == 1 && HIWORD(wParam) == 1000) {    // 1000 - це кастомний код для одинарного кліку (з ListBoxSubclassProc)
                PasteFromHistory(SendMessage(hListBox, LB_GETCURSEL, 0, 0));
            }
            break;

        case WM_VKEYTOITEM: // обробка клавіатури, коли фокус у ListBox
            if (LOWORD(wParam) == VK_RETURN) {  // Enter - вставити
                PasteFromHistory(SendMessage(hListBox, LB_GETCURSEL, 0, 0)); return -2; 
            }
            if (LOWORD(wParam) == VK_ESCAPE) { ShowWindow(hwnd, SW_HIDE); return -2; }  // Esc - закрити меню
            
            if (LOWORD(wParam) == VK_DELETE) {  // Delete - видалити запис  // перехоплюємо натискання клавіші
                int sel = SendMessage(hListBox, LB_GETCURSEL, 0, 0); // отримуємо виділену картку
                if (sel >= 0 && sel < g_VisualCount) {    // перевіряємо валідність виділення
                    bool isPinned = g_VisualMap[sel].isPinned;    // читаємо координати видалення з RAM-мапи
                    uint8_t realIdx = g_VisualMap[sel].realIdx;
                        
                    RemoveByRealIndex(realIdx, isPinned);  // переносимо запис у кошик (встановлюємо маркер Tombstone на диску та в RAM)
                    UpdateListBox();       // і оновлюємо відображення
                        
                    int count = SendMessage(hListBox, LB_GETCOUNT, 0, 0);   // зберігаємо виділення на сусідньому елементі після видалення
                    if (count > 0) SendMessage(hListBox, LB_SETCURSEL, sel >= count ? count - 1 : sel, 0);   // коригуємо індекс виділення, якщо елемент був останнім
                }
                return -2;  // повертаємо -2: повідомляємо Windows, що ми самі обробили клавішу
            }
            
            if (LOWORD(wParam) == VK_DOWN || LOWORD(wParam) == VK_UP) {  // циклічний скролінг стрілочками
                int curSel = SendMessage(hListBox, LB_GETCURSEL, 0, 0);
                int count = SendMessage(hListBox, LB_GETCOUNT, 0, 0);
                if (count > 0) {
                    if (LOWORD(wParam) == VK_DOWN) curSel = (curSel + 1) % count;
                    else if (LOWORD(wParam) == VK_UP) curSel = (curSel - 1 + count) % count;
                    SendMessage(hListBox, LB_SETCURSEL, curSel, 0);  // коригуємо індекс виділення
                    return -2;  // повідомляємо Windows, що ми самі обробили клавішу
                }
            }

            {    // ручний пошук по першому символу для навігації
                WORD vk = LOWORD(wParam); 
                // відтинаємо службові клавіші, реагуємо лише на літери, цифри та розділові знаки 
                if ((vk >= '0' && vk <= '9') || (vk >= 'A' && vk <= 'Z') || vk == VK_OEM_3 || (vk >= 0xBA && vk <= 0xC0) || (vk >= 0xDB && vk <= 0xDE)) { 
                    BYTE keyState[256]; 
                    GetKeyboardState(keyState); // читаємо фізичний стан клавіатури 
                    wchar_t chars[10] = {0}; 
                    UINT scanCode = MapVirtualKeyW(vk, MAPVK_VK_TO_VSC); // отримуємо скан-код клавіші 
                    
                    int res = ToUnicode(vk, scanCode, keyState, chars, 10, 0);    // перекладаємо віртуальну клавішу в реальний Юнікод-символ  
                    if (res > 0) { 
                        wchar_t typedChar = towupper(chars[0]); // переводимо введений символ у верхній регістр 
                        int curSel = SendMessage(hListBox, LB_GETCURSEL, 0, 0); 
                        int count = g_VisualCount; 
                        
                        if (count > 0) {     // шукаємо з наступного елемента після виділеного
                            int startIdx = (curSel + 1) % count;  
                            int foundIdx = -1; 
                            
                            AcquireSRWLockShared(&g_DataLock); // блокуємо буфер для безпечного читання 
                            for (int i = 0; i < count; i++) { 
                                int idx = (startIdx + i) % count; 
                                bool isPinned = g_VisualMap[idx].isPinned; 
                                uint8_t realIdx = g_VisualMap[idx].realIdx; 
                                ClipEntry& entry = isPinned ? pinnedBuffer[realIdx] : unpinnedBuffer[realIdx]; 
                                
                                // визначаємо, звідки прочитати текст 
                                const wchar_t* textPtr = (entry.textflags & TextFlags::File) ? entry.fileData.preview : entry.text;
                                int maxSafeLen = (entry.textLength > 988) ? 988 : entry.textLength;    // ліміт безпечного читання масиву в RAM
                                
                                if (maxSafeLen > 0) {    // перевірка абсолютного першого символу (дозволяє шукати по пробілу/табу)
                                    if (towupper(textPtr[0]) == typedChar) {
                                        foundIdx = idx;  // знайшли збіг, зберігаємо індекс
                                        break;  // зупиняємо цикл 
                                    }

                                    int skipLimit = (maxSafeLen > 32) ? 32 : maxSafeLen;    // пропуск відступів для коду (максимум 32 символи / 8 табів)
                                    int charOffset = 0; // ініціюємо нулем відлік
                                    
                                    while (charOffset < skipLimit &&  // перевіряємо символи шукаючи не-пробільний аж до 33-го
                                          (textPtr[charOffset] == L' ' || textPtr[charOffset] == L'\t' || 
                                           textPtr[charOffset] == L'\r' || textPtr[charOffset] == L'\n')) 
                                    {
                                        charOffset++;  // зсуваємо позицію далі
                                    }
                                    
                                    if (charOffset < maxSafeLen && textPtr[charOffset] != L'\0') {    // перевірка першої значущої літери після відступу
                                        if (towupper(textPtr[charOffset]) == typedChar) {     // порівнюємо першу літеру (також у верхньому регістрі) із тим, що ввів користувач 
                                            foundIdx = idx;  // знайшли збіг, зберігаємо індекс
                                            break;  // зупиняємо цикл 
                                        }
                                    }
                                }
                            }
                            ReleaseSRWLockShared(&g_DataLock); // знімаємо блокування даних 
                            
                            if (foundIdx != -1) { 
                                SendMessage(hListBox, LB_SETCURSEL, foundIdx, 0); // виділяємо знайдений елемент 
                                SendMessage(hListBox, LB_SETTOPINDEX, foundIdx, 0); // скролимо список 
                            }
                            return -2; // повідомляємо Windows, що ми обробили цю подію введення 
                        }
                    }
                }
            }
            return -1; // для всіх інших клавіш використовуємо стандартну поведінку Windows 

        case WM_ACTIVATE: // якщо юзер клікає поза вікном — ховаємо його
            if (LOWORD(wParam) == WA_INACTIVE) ShowWindow(hwnd, SW_HIDE); 
            break;

        case WM_CLOSE: // явне руйнування вікна
            DestroyWindow(hwnd);
            return 0;

        case WM_DESTROY: 
            ManageTrayIcon(hwnd, NIM_DELETE);  // видаляємо іконку з трею при закритті
            RemoveClipboardFormatListener(hwnd);
       
            if (g_hDbFile != INVALID_HANDLE_VALUE) {   // закриваємо глобальний дескриптор бази даних
                CloseHandle(g_hDbFile);
                g_hDbFile = INVALID_HANDLE_VALUE;
            }
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, msg, wParam, lParam); 
    }
    return 0;
}

// =|=|= вхід =|=|=
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // логіка м'ютексу (заборона множинних копій і реалізація Alt+Q як перемикача)
    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"Local\\LayoutClipboardMutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {    // якщо утиліта вже працює — знаходимо її вікно і кажемо закрити
        HWND hExistingWnd = FindWindowW(L"CustomClipboardMenu", NULL);
        if (hExistingWnd) PostMessage(hExistingWnd, WM_CLOSE, 0, 0);
        CloseHandle(hMutex);
        return 0; // завершуємо цей екземпляр
    }

    InitMaps(); 
    
    LoadHistory();     // тут ініціюємо g_hDbFile і виділяється місце на диску

    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    if (hUser32) {
        typedef BOOL(WINAPI *SetProcessDPIAwareFunc)();
        SetProcessDPIAwareFunc setDpiAware = (SetProcessDPIAwareFunc)GetProcAddress(hUser32, "SetProcessDPIAware");
        if (setDpiAware) setDpiAware();
    }

    InitGraphics(); // один викликлик на весь час роботи програми

    WNDCLASS wc = { 0 };      // реєструємо головне вікно
    wc.lpfnWndProc = WndProc; 
    wc.hInstance = hInstance;
    // намагаємось завантажити іконку з exe для вікна, або беремо стандартну
    wc.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_APPICON));
    if (!wc.hIcon) wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    
    wc.lpszClassName = L"CustomClipboardMenu";
    wc.hbrBackground = g_brMainBg; 
    RegisterClass(&wc);

    hMainWindow = CreateWindowEx(WS_EX_TOOLWINDOW | WS_EX_TOPMOST, L"CustomClipboardMenu", L"Буфер обміну",
        WS_POPUP, 0, 0, g_Config.winWidth, g_Config.winHeight, NULL, NULL, hInstance, NULL);

    WNDCLASS wcSet = { 0 };   // реєструємо вікно налаштувань
    wcSet.lpfnWndProc = SettingsWndProc; 
    wcSet.hInstance = hInstance;
    wcSet.hIcon = wc.hIcon;
    wcSet.lpszClassName = L"CustomClipboardSettings";
    wcSet.hbrBackground = g_brMainBg; 
    RegisterClass(&wcSet);
    
    // створюємо вікно налаштувань, але залишаємо його прихованим
    hSettingsWindow = CreateWindowEx(WS_EX_APPWINDOW, L"CustomClipboardSettings", L"Налаштування",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, 
        CW_USEDEFAULT, CW_USEDEFAULT, 400, 300, NULL, NULL, hInstance, NULL);
    
    g_hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, hInstance, 0);

    MSG msg = { 0 };
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    if (g_hKeyboardHook) UnhookWindowsHookEx(g_hKeyboardHook);
    CleanupGraphics();  // прибираємо за собою GDI ресурси
    CloseHandle(hMutex);     // звільнення мутексу при виході
    return 0;
}
