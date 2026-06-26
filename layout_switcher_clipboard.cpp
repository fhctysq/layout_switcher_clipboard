#define UNICODE
#define _UNICODE

// кажемо Windows використовувати сучасний візуальний стиль (для віконця і кнопок)
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "bcrypt.lib")

#include <windows.h> // Windows API
#include <windowsx.h> // macro APIs and control APIs
#include <uxtheme.h> // для доступу до системної теми
#include <strsafe.h> // Windows SDK designed to prevent security vulnerabilities
#include <shellapi.h> // для роботи з піктограмою в системному лотку (треї)
#include <cstdint> // для uint
#include <bcrypt.h>  // API (CNG) для шифрування

#ifndef NT_SUCCESS  // макрос перевірки успішності функцій CNG (щоб не підмикати важкий ntstatus.h)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// =|=|= візуальні налаштування інтерфейсу =|=|=
#define UI_WIN_WIDTH 560        // ширина головного вікна буфера
#define UI_WIN_HEIGHT 704       // висота головного вікна
#define UI_ITEM_HEIGHT 90       // висота однієї "картки" з текстом
#define UI_ITEM_GAP 8           // відступ між картками
#define UI_CORNER_RADIUS 18     // радіус заокруглення кутів вікна та карток
#define UI_PREVIEW_LENGTH 168   // скільки символів початку тексту показувати у прев'ю
#define UI_HEADER_HEIGHT 32     // висота верхньої "шапки" (за яку можна тягати вікно)
#define UI_BOTTOM_HEIGHT 32     // висота нижньої смужки для перетягування

// =|=|= налаштування трею та іконки =|=|=
#define WM_TRAYICON (WM_APP + 2) // кастомне повідомлення для обробки кліків у треї
#define IDI_APPICON 101          // id іконки в ресурсах (.rc файл)

// =|=|= налаштування пам'яті та безпеки =|=|=
#define LARGE_TEXT_THRESHOLD (16 * 1024) // якщо скопіювали більше 16 КБ за раз — скидаємо у файл
#define DISK_BLOCK_SIZE 16384 // 16 КБ блок на диску
#define RAM_BLOCK_SIZE 2048   // 2 КБ розмір структури в RAM
#define USER_KEY L"MySecretKey2026"  // увага: поки це лише ОБФУСКАЦІЯ (XOR), а не криптографічне шифрування

#define DB_FILE_NAME L"custom_clipboard.bin"
#define DB_FOLDER_NAME L"ClipboardData"
#define DB_FOLDER_PATH L"ClipboardData\\"

namespace DataFlags { // прапори даних про картку
    const uint8_t Empty     = 0;         // 0000 0000 (Комірка вільна / Tombstone)
    const uint8_t Used      = 1 << 0;    // 0000 0001 (Запис активний)
    const uint8_t CtrlC     = 1 << 1;    // 0000 0010 (Системний буфер)
    const uint8_t Micro     = 1 << 2;    // 0000 0100 (Мікротекст)
    const uint8_t Pinned    = 1 << 3;    // 0000 1000 (Закріплений)
    const uint8_t Encrypted = 1 << 4;    // 0001 0000 (Зашифрований)
}

namespace TextFlags { // прапори для обробки тексту
    const uint8_t None      = 0;
    const uint8_t Small     = 1 << 0;    // < 2 КБ (Текст повністю в RAM)
    const uint8_t Normal    = 1 << 1;    // 2 КБ - 16 КБ (Хвіст на диску)
    const uint8_t File      = 1 << 2;    // > 16 КБ (Хвіст в окремому файлі)
    const uint8_t Dynamic   = 1 << 3;    // Сенситивні дані (лише RAM, не пишемо на диск)
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
ClipEntry unpinnedBuffer[256] = { 0 }; // Основний масив
ClipEntry pinnedBuffer[256] = { 0 };   // Масив для закріплених записів

// лічильники з автообертанням (автоматично переходять 255 -> 0)
uint8_t unpinnedHead = 255; // починаємо з 255, щоб перше додавання (++head) записало в 0
uint8_t pinnedHead = 255;
int firstPinnedListIdx = -1; // зберігає позицію першого закріпленого запису в UI для швидкого стрибка

HWND hMainWindow = NULL;              // головне вікно програми
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

// === елементи для малювання (кольори, шрифти) ===
HBRUSH hDarkBrush = NULL; 
HFONT hFont = NULL; 
int g_ItemHeight = UI_ITEM_HEIGHT;

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
    PinCopy = 13, PinCut = 14, PinPaste = 15  // команди для роботи із закріпленими в буфері
};

// =|=|= словники для зміни розкладки =|=|=
wchar_t eng_to_ukr[65535]; 
wchar_t ukr_to_eng[65535]; 

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
    int count = sizeof(pairs) / sizeof(pairs[0]);
    for (int i = 0; i < count; ++i) {
        eng_to_ukr[pairs[i][0]] = pairs[i][1];
        ukr_to_eng[pairs[i][1]] = pairs[i][0];
    }
}

// =|=|= шифрування та файли =|=|=
// портативне CNG-шифрування (AES-256-CFB + SHA-256 Key Derivation) захищає збережені тексти на диску
void (BYTE* buffer, ULONG size, DWORD salt, bool isEncrypt) {
    if (size == 0) return;

    BCRYPT_ALG_HANDLE hHashAlg = NULL, hAesAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BYTE key[32] = { 0 }; // 32 байти для AES-256

    // генерація ключа (SHA-256: password + сіль)
    if (NT_SUCCESS(BCryptOpenAlgorithmProvider(&hHashAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) {
        if (NT_SUCCESS(BCryptCreateHash(hHashAlg, &hHash, NULL, 0, NULL, 0, 0))) {
            
            // змішуємо базовий ключ (пароль)
            BCryptHashData(hHash, (PUCHAR)USER_KEY, lstrlenW(USER_KEY) * sizeof(wchar_t), 0);
            BCryptHashData(hHash, (PUCHAR)&salt, sizeof(salt), 0);    // додаємо сіль (індекс комірки або час)
            
            BCryptFinishHash(hHash, key, sizeof(key), 0);   // отримуємо 32-байтний криптографічний ключ
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hHashAlg, 0);
    }
    // шифрування/розшифрування (AES-256-CFB)
    if (NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) {
        
        // (!) використовуємо режим CFB. тому що він не змінює розмір даних (немає Padding'у)
        BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CFB, sizeof(BCRYPT_CHAIN_MODE_CFB), 0);

        if (NT_SUCCESS(BCryptGenerateSymmetricKey(hAesAlg, &hKey, NULL, 0, key, sizeof(key), 0))) {
            ULONG resultLen = 0;
            BYTE iv[16] = { 0 }; // для CFB потрібен вектор ініціалізації. ключ уже унікалізований сіллю, нульовий IV безпечний

            if (isEncrypt) {   // шифруємо дані прямо в тому ж буфері (in-place)
                BCryptEncrypt(hKey, buffer, size, NULL, iv, sizeof(iv), buffer, size, &resultLen, 0);
            } else {       // розшифровуємо
                BCryptDecrypt(hKey, buffer, size, NULL, iv, sizeof(iv), buffer, size, &resultLen, 0);
            }
            BCryptDestroyKey(hKey);
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
// обчислює фізичний зсув (offset) блоку у файлі (2 байти суперблок + індекс * 16 КБ)
LARGE_INTEGER CalculateOffset(uint8_t index, bool isPinned) {
    LARGE_INTEGER offset;
    // додаємо базове зміщення 16 КБ (один порожній блок) під заголовок програми
    uint32_t baseOffset = DISK_BLOCK_SIZE + (isPinned ? (256 * DISK_BLOCK_SIZE) : 0);
    offset.QuadPart = baseOffset + (static_cast<uint32_t>(index) * DISK_BLOCK_SIZE);
    return offset;
}

void FormatPreviewForUI(const wchar_t* source, wchar_t* dest); // випереджаюче оголошення для UpdateListBox

// оновлює список текстів у вікні UI, відображаючи тільки активні записи з урахуванням Pinned і Unpinned масивів
void UpdateListBox() {
    SendMessage(hListBox, LB_RESETCONTENT, 0, 0); 
    wchar_t display[UI_PREVIEW_LENGTH + 5];
    firstPinnedListIdx = -1; // скидаємо перед перерахунком

    // спершу виводимо звичайні (Unpinned) записи від найновішого до найстарішого
    for (int i = 0; i < 256; i++) { // ітеруємо по буферу
        uint8_t realIdx = (unpinnedHead - i) & 255;
        ClipEntry& entry = unpinnedBuffer[realIdx];

        if (!(entry.dataflags & DataFlags::Used)) continue; // якщо комірка порожня/затомбстонена (кошик) — пропускаємо її
        FormatPreviewForUI(entry.text, display);
        wchar_t uiText[UI_PREVIEW_LENGTH + 20];
        if (entry.textflags & TextFlags::Dynamic) {  // перевірка на блискавку
            StringCchPrintfW(uiText, ARRAYSIZE(uiText), L"⚡ %s", display);  // візуальний маркер для RAM-only текстів
        } else {
            StringCchCopyW(uiText, ARRAYSIZE(uiText), display);
        }
        LRESULT listItemIdx = SendMessageW(hListBox, LB_ADDSTRING, 0, (LPARAM)uiText);
        SendMessage(hListBox, LB_SETITEMDATA, listItemIdx, (0 << 8) | realIdx); // маска координати: 0 = Unpinned
    }
    for (int i = 255; i >= 0; i--) { // ітеруємо по буферу закріплені (Pinned) записи
        uint8_t realIdx = (pinnedHead - i) & 255;
        ClipEntry& entry = pinnedBuffer[realIdx];
        
        if (!(entry.dataflags & DataFlags::Used)) continue; // якщо комірка порожня або затомбстонена (кошик) — пропускаємо її
        FormatPreviewForUI(entry.text, display);

        wchar_t uiText[UI_PREVIEW_LENGTH + 20];
        if (entry.textflags & TextFlags::Dynamic) {  // перевірка на блискавку і для запінених записів
            StringCchPrintfW(uiText, ARRAYSIZE(uiText), L"⚡ %s", display);
        } else {
            StringCchCopyW(uiText, ARRAYSIZE(uiText), display);
        }

        LRESULT listItemIdx = SendMessageW(hListBox, LB_ADDSTRING, 0, (LPARAM)uiText);
        SendMessage(hListBox, LB_SETITEMDATA, listItemIdx, (1 << 8) | realIdx); // маска координати: 1 = Pinned

        if (firstPinnedListIdx == -1) {  // запам'ятовуємо, де в переліку почався блок запінених
            firstPinnedListIdx = static_cast<int>(listItemIdx);
        }
    }
}

// =|=|= управління історіює та видаленими записами =|=|=

// функція записує блок (і за потреби хвіст або зовнішній файл)
void SaveBlockToDisk(uint8_t index, bool isPinned, const wchar_t* fullText) {
    ClipEntry& entry = isPinned ? pinnedBuffer[index] : unpinnedBuffer[index]; // отримуємо посилання на комірку відразу при вході
    
    HANDLE hFile = CreateFileW(DB_FILE_NAME, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        uint8_t heads[2] = { unpinnedHead, pinnedHead };  // зберігаємо лічильники на початку файлу (офсет 0)
        DWORD written;
        WriteFile(hFile, heads, 2, &written, NULL); // записуємо 2 байти лічильників на зміщення 0

        if (entry.textflags & TextFlags::Dynamic) {
            CloseHandle(hFile);
            return; // якщо це Dynamic (сенситивний запис), не пишемо його на диск і нічого не робимо
        }

        LARGE_INTEGER offset = CalculateOffset(index, isPinned); // стрибаємо до потрібного блоку
        SetFilePointerEx(hFile, offset, NULL, FILE_BEGIN);
       
        ClipEntry diskEntry = entry;
        DWORD slotSalt = (isPinned ? 1000 : 0) + index;
        SecureProcessBuffer((BYTE*)&diskEntry, RAM_BLOCK_SIZE, slotSalt, true);  // шифруємо копію структури метаданих перед записом на диск
        WriteFile(hFile, &diskEntry, RAM_BLOCK_SIZE, &written, NULL);    // записуємо 2 КБ (метадані + прев'ю)

        // якщо це Normal, дописуємо хвіст суворо в межах цього ж 16 КБ слота
        if (fullText && (entry.textflags & TextFlags::Normal) && entry.textLength > 1020) {
            DWORD tailBytes = (entry.textLength - 1020) * sizeof(wchar_t);
            BYTE* encTail = (BYTE*)HeapAlloc(GetProcessHeap(), 0, tailBytes);
            if (encTail) {
                memcpy(encTail, fullText + 1020, tailBytes);
                SecureProcessBuffer(encTail, tailBytes, slotSalt, true); // шифрування хвоста на диску
                WriteFile(hFile, encTail, tailBytes, &written, NULL);
                HeapFree(GetProcessHeap(), 0, encTail);
            }
        }
        CloseHandle(hFile);
    }

    // якщо це великий текст, виносимо файл в окрему папку
    if (fullText && (entry.textflags & TextFlags::File) && !(entry.textflags & TextFlags::Dynamic)) {
        wchar_t filepath[MAX_PATH];
        StringCchPrintfW(filepath, MAX_PATH, DB_FOLDER_PATH L"%s", entry.fileData.fileName);
        
        HANDLE hLargeFile = CreateFileW(filepath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hLargeFile != INVALID_HANDLE_VALUE) {
            DWORD fullBytes = entry.textLength * sizeof(wchar_t);
            BYTE* encBuffer = (BYTE*)HeapAlloc(GetProcessHeap(), 0, fullBytes);
            if (encBuffer) {
                memcpy(encBuffer, fullText, fullBytes);
                DWORD fileSalt = GetTickCount(); 
                SecureProcessBuffer(encBuffer, fullBytes, fileSalt, true);   // шифруємо весь файл
                DWORD written;
                WriteFile(hLargeFile, &fileSalt, sizeof(fileSalt), &written, NULL);   // зберігаємо сіль (4 байти) на початку файлу
                WriteFile(hLargeFile, encBuffer, fullBytes, &written, NULL);
                HeapFree(GetProcessHeap(), 0, encBuffer);
            }
            CloseHandle(hLargeFile);
        }
    }
}

// функція видаляє картки - переміщує запис в кошик (Tombstoning) - за справжнім індексом буфера
void RemoveByRealIndex(uint8_t index, bool isPinned) {
    ClipEntry& entry = isPinned ? pinnedBuffer[index] : unpinnedBuffer[index];
    if (!(entry.dataflags & DataFlags::Used)) return; // якщо запис уже порожній або затомбстонений — нічого не робимо

    // якщо це великий текст — перейменовуємо його файл під кошик
    if (entry.textflags & TextFlags::File) {
        wchar_t oldPath[MAX_PATH];
        wchar_t newPath[MAX_PATH];
        wchar_t newFileName[32];
        StringCchPrintfW(newFileName, 32, L"trashed_%s", entry.fileData.fileName); // нове ім'я файлу з префіксом trashed_
        
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

    SaveBlockToDisk(index, isPinned, NULL); // зберігаємо оновлену затомбстонену картку на диск
}

// =|=|= обробка закріплених записів =|=|=
// функція переносить запис між двома барабанами (звичайного і закріпленого)
void TogglePinState(uint8_t realIdx, bool currentlyPinned) {
    // визначаємо джерело (звідки беремо)
    ClipEntry& sourceEntry = currentlyPinned ? pinnedBuffer[realIdx] : unpinnedBuffer[realIdx];
    if (!(sourceEntry.dataflags & DataFlags::Used)) return;

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
        if (normalTail) {
            LARGE_INTEGER sourceOffset = CalculateOffset(realIdx, currentlyPinned);
            sourceOffset.QuadPart += RAM_BLOCK_SIZE; // зсув на хвіст
            
            HANDLE hFileR = CreateFileW(DB_FILE_NAME, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFileR != INVALID_HANDLE_VALUE) {
                SetFilePointerEx(hFileR, sourceOffset, NULL, FILE_BEGIN);
                DWORD br; ReadFile(hFileR, normalTail, tailBytes, &br, NULL); // читаємо хвіст прямо в XOR-і
                DWORD sourceSalt = (currentlyPinned ? 1000 : 0) + realIdx;
                SecureProcessBuffer((BYTE*)normalTail, br, sourceSalt, false); // розшифровуємо зі старого слоту
                CloseHandle(hFileR);
            }
        }
    }

    sourceEntry.dataflags = DataFlags::Empty; // позначаємо перенесений запис Empty в попередньому переліку

    // синхронізуємо з диском (один вхід до файлу для чотирьох задач)
    HANDLE hFileW = CreateFileW(DB_FILE_NAME, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFileW != INVALID_HANDLE_VALUE) {
        DWORD written;
        
        // 1: оновлюємо глобальні лічильники в суперблоці (офсет 0)
        uint8_t heads[2] = { unpinnedHead, pinnedHead };
        WriteFile(hFileW, heads, 2, &written, NULL);

        // 2: записуємо нову комірку (метадані + прев'ю)
        LARGE_INTEGER targetOffset = CalculateOffset(targetIdx, !currentlyPinned);
        SetFilePointerEx(hFileW, targetOffset, NULL, FILE_BEGIN);
        // записуємо зашифровані метадані в новий слот цільового барабану
        ClipEntry diskTargetEntry = targetEntry;
        DWORD targetSalt = (!currentlyPinned ? 1000 : 0) + targetIdx;
        SecureProcessBuffer((BYTE*)&diskTargetEntry, RAM_BLOCK_SIZE, targetSalt, true);
        WriteFile(hFileW, &diskTargetEntry, RAM_BLOCK_SIZE, &written, NULL);

        // 3: якщо був хвіст Normal-тексту, записуємо його у новий офсет
        if (normalTail) {
            WriteFile(hFileW, normalTail, tailBytes, &written, NULL);
        }

        // 4: позначаємо стару комірку на диску Empty
        LARGE_INTEGER sourceOffset = CalculateOffset(realIdx, currentlyPinned);
        SetFilePointerEx(hFileW, sourceOffset, NULL, FILE_BEGIN);
        ClipEntry diskSourceEntry = sourceEntry;
        DWORD sourceSalt = (currentlyPinned ? 1000 : 0) + realIdx;
        SecureProcessBuffer((BYTE*)&diskSourceEntry, RAM_BLOCK_SIZE, sourceSalt, true);
        WriteFile(hFileW, &diskSourceEntry, RAM_BLOCK_SIZE, &written, NULL);

        CloseHandle(hFileW);
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
        bool isKeyDown = (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN);
        bool isKeyUp = (wParam == WM_KEYUP || wParam == WM_SYSKEYUP);
        
        bool isLeftAltPressed = (GetAsyncKeyState(VK_LMENU) & 0x8000) != 0;
        bool isRightAltPressed = (GetAsyncKeyState(VK_RMENU) & 0x8000) != 0;
        bool isCtrlPressed = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;

        // відстеження CTRL+A
        static bool ctrlA_handled = false;
        if (pKeyBoard->vkCode == 'A') {
            if (isKeyDown) {
                if (isCtrlPressed && !isLeftAltPressed && !isRightAltPressed) {
                    if (!ctrlA_handled) {
                        ctrlA_handled = true;
                        // сигналізуємо системі про натиснутий Ctrl+A.
                        PostMessage(hMainWindow, MSG_PROCESS_HOTKEY, static_cast<WPARAM>(HotkeyCmd::SilentCopyAll), 0);
                    }
                }
            } else if (isKeyUp) {
                ctrlA_handled = false; 
            }
        }

        if (isKeyDown) {
            // перевіряємо комбінацію Alt+Win або Win+Alt при відкритому меню
            if (IsWindowVisible(hMainWindow)) {
                bool isWin = (pKeyBoard->vkCode == VK_LWIN || pKeyBoard->vkCode == VK_RWIN);
                bool isAlt = (pKeyBoard->vkCode == VK_LMENU || pKeyBoard->vkCode == VK_RMENU);
                
                // якщо одна з них натиснута, а інша вже утримується фізично
                if ((isWin && ((GetAsyncKeyState(VK_LMENU) & 0x8000) || (GetAsyncKeyState(VK_RMENU) & 0x8000))) ||
                    (isAlt && ((GetAsyncKeyState(VK_LWIN) & 0x8000) || (GetAsyncKeyState(VK_RWIN) & 0x8000)))) 
                {
                    int sel = SendMessage(hListBox, LB_GETCURSEL, 0, 0);
                    if (sel >= 0) {
                        LRESULT itemData = SendMessage(hListBox, LB_GETITEMDATA, sel, 0);
                        if (itemData != LB_ERR) {
                            bool isPinned = (itemData >> 8) & 1;
                            uint8_t realIdx = itemData & 0xFF;
                            
                            TogglePinState(realIdx, isPinned);
                            
                            UpdateListBox(); // оновлюємо UI та зберігаємо виділення на тій самій позиції
                            int count = SendMessage(hListBox, LB_GETCOUNT, 0, 0);
                            if (count > 0) SendMessage(hListBox, LB_SETCURSEL, sel >= count ? count - 1 : sel, 0);
                        }
                    }
                    CancelWindowsMenuFocus();
                    return 1; // блокуємо подальше спливання клавіш в ОС
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

// функція генерує компактне ім'я для відокремлених файлів - понад 16 КБ - (формат: РРММДД_ГГХХСС_текст.bin)
void GenerateLargeFileName(wchar_t* outName, const wchar_t* sourceText) {
    SYSTEMTIME st;
    GetLocalTime(&st); // отримуємо поточний локальний час системи
    
    // створюємо короткий префікс часу: РРММДД_ГГХХСС (st.wYear % 100 забирає лише останні 2 цифри року)
    wchar_t timeStr[16];
    StringCchPrintfW(timeStr, 16, L"%02d%02d%02d_%02d%02d%02d", st.wYear % 100, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    // витягаємо безпечні символи тексту (до 17 символів)
    wchar_t cleanText[19] = {0}; // 17 символів + можливе фінальне підкреслення + нуль
    int j = 0;
    for (int i = 0; sourceText[i] != L'\0' && j < 17; i++) { // біжимо по тексту, поки не наберемо 17 чистих чарів
        wchar_t c = sourceText[i];
        if (c == L'\r' || c == L'\n' || c == L'\t' || c == L' ') { // замінюємо всі переноси та пробіли на підкреслення
            if (j > 0 && cleanText[j-1] != L'_') cleanText[j++] = L'_';
            continue;
        }
        if (wcschr(L"\\/:*?\"<>|", c) == NULL) { // якщо символ не заборонений файловою системою Windows
            cleanText[j++] = c; // копіюємо його в ім'я файлу
        }
    }
    if (j > 0 && cleanText[j-1] == L'_') cleanText[j-1] = L'\0'; // прибираємо підкреслення на кінці, якщо воно там залишилось

    // збираємо фінальне ім'я у буфер картки (максимум 31 символ + нуль-термінатор)
    if (j > 0) {
        StringCchPrintfW(outName, 32, L"%s_%s.bin", timeStr, cleanText); // якщо текст наявний: 260524_235959_MyText.bin
    } else {
        StringCchPrintfW(outName, 32, L"%s_file.bin", timeStr); // якщо тексту немає взагалі: 260524_235959_file.bin
    }
}

// додаємо новий запис в історію в кільцевий буфер RAM
void AddToHistory(const wchar_t* text, uint16_t extraDataFlags = 0, uint16_t extraTextFlags = 0) {
    if (!text) return;
    uint32_t len = lstrlenW(text);
    if (len == 0) return; // вихід, якщо новий "текст" порожній

    // дедуплікація: ігноруємо текст, якщо він ідентичний попередньому
    ClipEntry& lastEntry = unpinnedBuffer[unpinnedHead];
    if ((lastEntry.dataflags & DataFlags::Used) && lastEntry.textLength == len) {
        int checkLen = (len < 1020) ? len : 988;
        if (wcsncmp(lastEntry.text, text, checkLen) == 0) return; 
    }

    // зсуваємо голову буфера (автообертання 255 -> 0 працює апаратно)
    unpinnedHead++; 
    ClipEntry& entry = unpinnedBuffer[unpinnedHead];

    // якщо в комірці був старий запис (File) — чистимо його у сховищі
    if (entry.dataflags & DataFlags::Used) {
        RemoveByRealIndex(unpinnedHead, false);
    }

    // заповнюємо 8 байтів нових метаданих
    entry.textLength = len;
    entry.dataflags = DataFlags::Used | extraDataFlags;
    entry.textflags = TextFlags::None | extraTextFlags;

    // сортування за розміром (межа 16 КБ в байтах = 8192 символи wchar_t)
    if (len <= 1020) {
        entry.textflags |= TextFlags::Small;
        wcsncpy_s(entry.text, 1020, text, _TRUNCATE);
    } 
    else if (len <= 8192) { 
        entry.textflags |= TextFlags::Normal;
        // копіюємо перші 1020 символів як inline-прев'ю (затре reserved поля на диску, що безпечно)
        wcsncpy_s(entry.text, 1020, text, _TRUNCATE); 
    } 
    else {
        entry.textflags |= TextFlags::File;
        wcsncpy_s(entry.fileData.preview, 988, text, _TRUNCATE);
        GenerateLargeFileName(entry.fileData.fileName, text);   // створюємо назву файлу
        CreateDirectoryW(DB_FOLDER_NAME, NULL);
    }

    // синхронізуємо стан з диском
    SaveBlockToDisk(unpinnedHead, false, text);
}

// функція відновлює індексну карту прев'ю після перезапуску за мілісекунди
void LoadHistory() {
    HANDLE hFile = CreateFileW(DB_FILE_NAME, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD read;
        uint8_t heads[2] = { 255, 255 };
        
        // читаємо і відновлюємо глобальні лічильники кільцевого буфера
        if (ReadFile(hFile, heads, 2, &read, NULL) && read == 2) {
            unpinnedHead = heads[0];
            pinnedHead = heads[1];
        }

        // завантажуємо тільки індексні картки (по 2 КБ) для звичайних записів
        for (int i = 0; i < 256; i++) {
            LARGE_INTEGER offset = CalculateOffset(i, false);
            SetFilePointerEx(hFile, offset, NULL, FILE_BEGIN);
            ReadFile(hFile, &unpinnedBuffer[i], RAM_BLOCK_SIZE, &read, NULL);
            if (read == RAM_BLOCK_SIZE && (unpinnedBuffer[i].dataflags & DataFlags::Used)) {
                DWORD slotSalt = i; // !isPinned
                SecureProcessBuffer((BYTE*)&unpinnedBuffer[i], RAM_BLOCK_SIZE, slotSalt, false);
            }
        }
        for (int i = 0; i < 256; i++) { // також тільки індексні картки (по 2 КБ) для закріплених записів
            LARGE_INTEGER offset = CalculateOffset(i, true);
            SetFilePointerEx(hFile, offset, NULL, FILE_BEGIN);
            ReadFile(hFile, &pinnedBuffer[i], RAM_BLOCK_SIZE, &read, NULL);
            if (read == RAM_BLOCK_SIZE && (pinnedBuffer[i].dataflags & DataFlags::Used)) {
                DWORD slotSalt = 1000 + i; // isPinned
                SecureProcessBuffer((BYTE*)&pinnedBuffer[i], RAM_BLOCK_SIZE, slotSalt, false);
            }
        }
        CloseHandle(hFile);
    }
}

// логіка ледачого завантаження (Lazy Loading), читаємо повний запис у виділену пам'ять (викликається перед Ctrl+V)
wchar_t* LoadTextByRealIndex(uint8_t index, bool isPinned) {
    ClipEntry& entry = isPinned ? pinnedBuffer[index] : unpinnedBuffer[index];
    if (!(entry.dataflags & DataFlags::Used)) return NULL;

    // динамічно просимо пам'ять у системи суворо під розмір тексту (+1 для нуль-термінатора рядка)
    wchar_t* targetBuffer = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, (entry.textLength + 1) * sizeof(wchar_t));
    if (!targetBuffer) return NULL;

    if (entry.textflags & TextFlags::Small) {
        // варіант А: Текст повністю лежить в RAM
        memcpy(targetBuffer, entry.text, entry.textLength * sizeof(wchar_t));
    } 
    else if (entry.textflags & TextFlags::Normal) {
        // варіант Б: Забираємо inline-частину (перші 1020 символів) з RAM
        memcpy(targetBuffer, entry.text, 1020 * sizeof(wchar_t));
        
        // дочитуємо решту тексту ("хвіст") зі сховища за O(1)
        HANDLE hFile = CreateFileW(DB_FILE_NAME, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER offset = CalculateOffset(index, isPinned);
            offset.QuadPart += RAM_BLOCK_SIZE; // стрибаємо повз 2 КБ картки прев'ю на початок хвоста
            SetFilePointerEx(hFile, offset, NULL, FILE_BEGIN);
            
            DWORD bytesToRead = (entry.textLength - 1020) * sizeof(wchar_t);
            DWORD bytesRead;
            ReadFile(hFile, targetBuffer + 1020, bytesToRead, &bytesRead, NULL);
            DWORD slotSalt = (isPinned ? 1000 : 0) + index;
            SecureProcessBuffer((BYTE*)(targetBuffer + 1020), bytesRead, slotSalt, false); // знімаємо обфускацію з хвоста
            CloseHandle(hFile);
        }
    } 
    else if (entry.textflags & TextFlags::File) {
        // варіант В: текст великий, читаємо його з окремого зовнішнього файлу
        wchar_t filepath[MAX_PATH];
        StringCchPrintfW(filepath, MAX_PATH, DB_FOLDER_PATH L"%s", entry.fileData.fileName);
        HANDLE hFile = CreateFileW(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD fileSalt = 0;
            DWORD bytesRead = 0;
            ReadFile(hFile, &fileSalt, sizeof(fileSalt), &bytesRead, NULL);   // читаємо унікальну сіль файлу (перші 4 байти)
            DWORD bytesToRead = entry.textLength * sizeof(wchar_t);
            ReadFile(hFile, targetBuffer, bytesToRead, &bytesRead, NULL);
            SecureProcessBuffer((BYTE*)targetBuffer, bytesRead, fileSalt, false);  // розшифровуємо все тіло файлу
            CloseHandle(hFile);
        } else {
            StringCchCopyW(targetBuffer, entry.textLength + 1, L"[ПОМИЛКА] Зовнішній файл не знайдено.");
        }
    }

    targetBuffer[entry.textLength] = L'\0'; // ставимо фінальний маркер кінця рядка
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
        EmptyClipboard();  // очищуємо його (тепер наше вікно власник буфера)
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
                if (copyDirectToPinned) {
                    pinnedHead++; // тимчасово зсуваємо pinnedHead вперед і робимо запис через проміжну змінну
                    ClipEntry& entry = pinnedBuffer[pinnedHead];
                    if (entry.dataflags & DataFlags::Used) {
                        RemoveByRealIndex(pinnedHead, true);
                    }
                    uint32_t len = lstrlenW(pText);
                    entry.textLength = len;
                    entry.dataflags = DataFlags::Used | DataFlags::Pinned | (setAsAltC ? DataFlags::CtrlC : 0);
                    
                    if (len <= 1020) {
                        entry.textflags = TextFlags::Small;
                        wcsncpy_s(entry.text, 1020, pText, _TRUNCATE);
                    } else if (len <= 8192) {
                        entry.textflags = TextFlags::Normal;
                        wcsncpy_s(entry.text, 1020, pText, _TRUNCATE);
                    } else {
                        entry.textflags = TextFlags::File;
                        wcsncpy_s(entry.fileData.preview, 988, pText, _TRUNCATE);
                        GenerateLargeFileName(entry.fileData.fileName, pText);
                        CreateDirectoryW(DB_FOLDER_NAME, NULL);
                    }
                    SaveBlockToDisk(pinnedHead, true, pText);
                    
                    if (setAsAltC) {
                        lastAltCIndex = pinnedHead;  // запам'ятовуємо індекс закріпленої картки кільцевого буфера
                        lastAltCIsPinned = true;
                    }
                } else {
                    AddToHistory(pText, setAsAltC ? DataFlags::CtrlC : 0);  // зберігаємо текст в історію (він стане на позицію unpinnedHead)
                    if (setAsAltC) {
                        lastAltCIndex = unpinnedHead;  // запам'ятовуємо індекс картки кільцевого буфера для Alt+V
                        lastAltCIsPinned = false;
                    }
                }
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
        EmptyClipboard();
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
    if (textToPaste) HeapFree(GetProcessHeap(), 0, textToPaste); // чистимо оперативку після того, як ОС забрала текст
    RestoreSysClipboard(); 
    ClearPendingClipboardUpdates();
    ignoreClipboardUpdate = false;
}
// вставка конкретного тексту з історії (вибір через віконце)
void PasteFromHistory(int index) {
    if (index < 0) return;

    // розпаковуємо індекс і прапорець з меню
    LRESULT itemData = SendMessage(hListBox, LB_GETITEMDATA, index, 0);
    if (itemData == LB_ERR) return;

    bool isPinned = (itemData >> 8) & 1;
    uint8_t realIdx = itemData & 0xFF;
    
    if (!((GetAsyncKeyState(VK_LMENU) & 0x8000) || (GetAsyncKeyState(VK_RMENU) & 0x8000))) {
        ShowWindow(hMainWindow, SW_HIDE);   // ховаємо віконце лише якщо користувач не утримує клавішу Alt
    }
    ignoreClipboardUpdate = true; 
    BackupSysClipboard();

    wchar_t* textToPaste = LoadTextByRealIndex(realIdx, isPinned);
    if (textToPaste && OpenClipboard(NULL)) {
        EmptyClipboard();
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
    }
    RestoreSysClipboard(); 
    ClearPendingClipboardUpdates();
    ignoreClipboardUpdate = false;

    // піднімаємо використаний текст нагору списку (якщо він не Pinned)
    if (textToPaste && !isPinned && realIdx != unpinnedHead) {
        RemoveByRealIndex(realIdx, false);
        AddToHistory(textToPaste);
    }

    if (textToPaste) HeapFree(GetProcessHeap(), 0, textToPaste); 
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
                        for (size_t i = 0; i < len; ++i) {
                            wchar_t ch = pText[i];  // копіюємо кожен поточний символ
                            if (mode == TransformMode::Layout) {
                                if (eng_to_ukr[ch]) { pNewText[i] = eng_to_ukr[ch]; changed = true; toUkrCount++; } // англ -> укр
                                else if (ukr_to_eng[ch]) { pNewText[i] = ukr_to_eng[ch]; changed = true; toEngCount++; } // укр -> англ
                                else { pNewText[i] = ch; } // цифри, пробіли
                            } else if (mode == TransformMode::Case) { // інверсія регістру
                                WCHAR c = ch;
                                if (IsCharUpperW(c)) { 
                                    CharLowerBuffW(&c, 1); 
                                    pNewText[i] = c; 
                                    changed = true; 
                                }
                                else if (IsCharLowerW(c)) { 
                                    CharUpperBuffW(&c, 1); 
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
                        EmptyClipboard();  // очищуємо буфер обміну
                        SetClipboardData(CF_UNICODETEXT, hNewData);  // віддаємо ОС блок даних
                        GlobalUnlock(hData);  // розблоковуємо системний буфер обміну
                        CloseClipboard();  // закриваємо сесію Clipboard API

                        SendKeyCombo(VK_CONTROL, 0x56);  // імітуємо Ctrl+V
                        Sleep(60); 
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
void FormatPreviewForUI(const wchar_t* source, wchar_t* dest) {
    int j = 0;
    for (int k = 0; source[k] != L'\0' && j < UI_PREVIEW_LENGTH; k++) {
        if (source[k] == L'\r') continue; // ігноруємо переміщення курсора на початок поточного рядка 
        if (source[k] == L'\n') { dest[j++] = L' '; continue; }  // замінюємо переноси на пробіли
        dest[j++] = source[k];
    }
    if (lstrlenW(source) > UI_PREVIEW_LENGTH && j <= UI_PREVIEW_LENGTH) {
        StringCchCopyW(dest + j, (UI_PREVIEW_LENGTH + 5) - j, L"..."); // якщо текст більший ліміту — додаємо три крапки
    } else {
        dest[j] = L'\0';
    }
}


// відображає вікно історії справа вгорі активного вікна
void ShowClipboardUI(bool selectLast = false) {
    UpdateListBox();
    
    int count = SendMessage(hListBox, LB_GETCOUNT, 0, 0);
    if (count > 0) {
        SendMessage(hListBox, LB_SETCURSEL, selectLast ? count - 1 : 0, 0);
    }
    
    HWND hActive = GetForegroundWindow(); 
    RECT rect;
    int width = UI_WIN_WIDTH; 
    int height = UI_WIN_HEIGHT; 
    int x = 0, y = 0;
    
    // намагаємось вивести вікно поруч з активним додатком, або на позиції курсору
    if (hActive && GetWindowRect(hActive, &rect)) {
        x = rect.right - width - 20;
        y = rect.top + 20;
    } else {
        POINT pt; GetCursorPos(&pt); x = pt.x; y = pt.y;
    }

    SetWindowPos(hMainWindow, HWND_TOPMOST, x, y, width, height, SWP_SHOWWINDOW);
    HRGN hRgn = CreateRoundRectRgn(0, 0, width, height, UI_CORNER_RADIUS, UI_CORNER_RADIUS);
    
    SetWindowRgn(hMainWindow, hRgn, TRUE);   
    SetForegroundWindow(hMainWindow);
    SetFocus(hListBox);
}

// колбек для перехоплення кліків мишею по списку (Listbox)
LRESULT CALLBACK ListBoxSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
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
            int cardRight = itemRect.right - UI_ITEM_GAP;
            int cardBottom = itemRect.bottom - (UI_ITEM_GAP / 2);
            int btnRight = cardRight - 10;
            int btnLeft = btnRight - 32;
            int btnBottom = cardBottom - 10;
            int btnTop = btnBottom - 32;
            
            // якщо клік саме по кнопці (32x32 пікселі у кутку)
            if (clickX >= btnLeft && clickX <= btnRight && clickY >= btnTop && clickY <= btnBottom) {
                LRESULT itemData = SendMessage(hwnd, LB_GETITEMDATA, selIdx, 0);
                if (itemData != LB_ERR) {
                    bool isPinned = (itemData >> 8) & 1;
                    uint8_t realIdx = itemData & 0xFF;
                    
                    TogglePinState(realIdx, isPinned);
                    UpdateListBox();
                    
                    int count = SendMessage(hwnd, LB_GETCOUNT, 0, 0);
                    if (count > 0) SendMessage(hwnd, LB_SETCURSEL, selIdx >= count ? count - 1 : selIdx, 0);
                }
                return 0; // перехопили клік, не виконуємо стандартну вставку тексту
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

// =|=|= головний обробник вікна =|=|=
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: 
            ManageTrayIcon(hwnd, NIM_ADD); // реєструємо іконку в треї при старті

            hListBox = CreateWindowEx(0, L"LISTBOX", NULL,
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY | LBS_WANTKEYBOARDINPUT | LBS_HASSTRINGS | LBS_OWNERDRAWFIXED | LBS_NOINTEGRALHEIGHT,
                0, UI_HEADER_HEIGHT, UI_WIN_WIDTH, UI_WIN_HEIGHT - UI_HEADER_HEIGHT - UI_BOTTOM_HEIGHT, hwnd, (HMENU)1, NULL, NULL);
            
            SendMessage(hListBox, WM_SETFONT, (WPARAM)hFont, TRUE);
            SetWindowTheme(hListBox, L"DarkMode_Explorer", NULL);

            OldListBoxProc = (WNDPROC)SetWindowLongPtr(hListBox, GWLP_WNDPROC, (LONG_PTR)ListBoxSubclassProc);
            AddClipboardFormatListener(hwnd); // програма стає слухачем системного буфера обміну
            break;

        case WM_TRAYICON: // обробка кліків по іконці в треї
            if (lParam == WM_RBUTTONUP) {
                POINT pt; GetCursorPos(&pt);
                HMENU hMenu = CreatePopupMenu();
                InsertMenuW(hMenu, -1, MF_BYPOSITION | MF_STRING, 1, L"Вихід");
                
                SetForegroundWindow(hwnd); // фокус, щоб меню коректно закривалось при кліку повз
                int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, hwnd, NULL);
                DestroyMenu(hMenu);
                
                if (cmd == 1) SendMessage(hwnd, WM_CLOSE, 0, 0);
            } else if (lParam == WM_LBUTTONDBLCLK) {
                ShowClipboardUI(false);
            }
            break;

        case WM_NCHITTEST: { // дозволяємо тягати вікно за шапку і за нижню смужку
            LRESULT hit = DefWindowProc(hwnd, msg, wParam, lParam);
            if (hit == HTCLIENT) {
                POINT pt;
                pt.x = GET_X_LPARAM(lParam);
                pt.y = GET_Y_LPARAM(lParam);
                ScreenToClient(hwnd, &pt);
                
                if (pt.y < UI_HEADER_HEIGHT) {
                    if (pt.x >= UI_WIN_WIDTH - UI_HEADER_HEIGHT) return HTCLIENT; 
                    return HTCAPTION; 
                }
                if (pt.y > UI_WIN_HEIGHT - UI_BOTTOM_HEIGHT) {
                    return HTCAPTION; 
                }
            }
            return hit;
        }

        case WM_LBUTTONDOWN: { // клік по кнопці закриття "✕"
            POINT pt;
            pt.x = GET_X_LPARAM(lParam);
            pt.y = GET_Y_LPARAM(lParam);
            if (pt.y < UI_HEADER_HEIGHT && pt.x >= UI_WIN_WIDTH - UI_HEADER_HEIGHT) {
                // перевірка Shift для повного закриття, інакше тільки ховаємо віконце
                if (GetKeyState(VK_SHIFT) & 0x8000) {
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
            SelectObject(hdc, hFont);

            RECT rcHeader = {0, 0, UI_WIN_WIDTH - UI_HEADER_HEIGHT, UI_HEADER_HEIGHT}; 
            DrawTextW(hdc, L"  ≡ Кастомний Буфер (Alt+Q — вихід)", -1, &rcHeader, DT_SINGLELINE | DT_VCENTER);

            RECT rcClose = {UI_WIN_WIDTH - UI_HEADER_HEIGHT, 0, UI_WIN_WIDTH, UI_HEADER_HEIGHT};
            SetTextColor(hdc, RGB(220, 110, 110)); 
            DrawTextW(hdc, L"✕", -1, &rcClose, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            RECT rcBottom = {0, UI_WIN_HEIGHT - UI_BOTTOM_HEIGHT, UI_WIN_WIDTH, UI_WIN_HEIGHT};
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
            mis->itemHeight = g_ItemHeight; 
            return TRUE;
        }

        case WM_DRAWITEM: { // кастомне малювання одного запису (округлені картки)
            DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lParam;
            if (dis->itemID == -1) break;  // 

            HDC hdc = dis->hDC;
            RECT rc = dis->rcItem;
            bool isSelected = (dis->itemState & ODS_SELECTED); 

            RECT cardRect = rc;
            cardRect.left += UI_ITEM_GAP; cardRect.right -= UI_ITEM_GAP;
            cardRect.top += UI_ITEM_GAP / 2; cardRect.bottom -= UI_ITEM_GAP / 2;

            HBRUSH bgBrush = CreateSolidBrush(isSelected ? RGB(70, 70, 75) : RGB(45, 45, 45));
            HPEN borderPen = CreatePen(PS_SOLID, 1, isSelected ? RGB(100, 100, 110) : RGB(60, 60, 60));
            HGDIOBJ oldBrush = SelectObject(hdc, bgBrush);
            HGDIOBJ oldPen = SelectObject(hdc, borderPen);
            // малювання RoundRect для фону картки
            RoundRect(hdc, cardRect.left, cardRect.top, cardRect.right, cardRect.bottom, UI_CORNER_RADIUS, UI_CORNER_RADIUS);
            SelectObject(hdc, oldBrush); SelectObject(hdc, oldPen);
            DeleteObject(bgBrush); DeleteObject(borderPen);

            // розпаковуємо дані, щоб знати стан запису
            LRESULT itemData = SendMessage(dis->hwndItem, LB_GETITEMDATA, dis->itemID, 0);
            bool isPinned = (itemData != LB_ERR) ? ((itemData >> 8) & 1) : false;

            SetBkMode(hdc, TRANSPARENT);

            wchar_t text[UI_PREVIEW_LENGTH + 20]; // малюємо текст
            SendMessage(dis->hwndItem, LB_GETTEXT, dis->itemID, (LPARAM)text);
            SetTextColor(hdc, RGB(240, 240, 240));

            RECT textRect = cardRect;
            textRect.left += 14; textRect.right -= 14; // відступ на початку і в кінці на 14
            textRect.top += 10; textRect.bottom -= 10;  // відступ згори 10
            DrawTextW(hdc, text, -1, &textRect, DT_WORDBREAK | DT_END_ELLIPSIS | DT_NOPREFIX);

            RECT btnRect;  // малюємо кнопку піна (понад тексту, у правому нижньому кутку)
            btnRect.right = cardRect.right - 8;          // правий відступ від краю картки
            btnRect.left = btnRect.right - 36;            // ширина кнопки: 36px
            btnRect.bottom = cardRect.bottom - 8;        // відступ від низу картки
            btnRect.top = btnRect.bottom - 36;            // висота кнопки: 36px
            
            // малюємо фон самої кнопки (яскравий, якщо закріплено)
            HBRUSH btnBrush = CreateSolidBrush(RGB(50, 50, 55));
            HPEN btnPen = CreatePen(PS_SOLID, 1, RGB(80, 80, 85));
            oldBrush = SelectObject(hdc, btnBrush);
            oldPen = SelectObject(hdc, btnPen);
            RoundRect(hdc, btnRect.left, btnRect.top, btnRect.right, btnRect.bottom, 14, 14);  // заокруглення 14px
            SelectObject(hdc, oldBrush); SelectObject(hdc, oldPen);
            DeleteObject(btnBrush); DeleteObject(btnPen);
            
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
            else if (cmd == HotkeyCmd::PinPaste) {
                // вставка останнього саме закріпленого запису (шукаємо останній Used у pinned буфері)
                if (pinnedBuffer[pinnedHead].dataflags & DataFlags::Used) {
                    ignoreClipboardUpdate = true;
                    BackupSysClipboard();
                    wchar_t* textToPaste = LoadTextByRealIndex(pinnedHead, true);
                    if (textToPaste && OpenClipboard(NULL)) {
                        EmptyClipboard();
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
                    }
                    if (textToPaste) HeapFree(GetProcessHeap(), 0, textToPaste);
                    RestoreSysClipboard();
                    ClearPendingClipboardUpdates();
                    ignoreClipboardUpdate = false;
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
            else if (cmd == HotkeyCmd::SilentCopyAll) { 
                // замість блокуючого Sleep(150), який заморожував програму, 
                // запускаємо таймер. програма-донор встигає відпрацювати Ctrl+A.
                SetTimer(hwnd, 2026, 200, NULL);
            }
            else if (cmd == HotkeyCmd::StrikeSlanted) { TransformClipboardText(TransformMode::StrikeSlanted); } 
            else if (cmd == HotkeyCmd::StrikeStraight) { TransformClipboardText(TransformMode::StrikeStraight); } 
            break;
        }

        case WM_CTLCOLORLISTBOX: { // фарбуємо фон Listbox
            HDC hdc = (HDC)wParam;
            SetBkColor(hdc, RGB(25, 25, 25));       
            SetTextColor(hdc, RGB(240, 240, 240));  
            return (LRESULT)hDarkBrush;             
        }

        case WM_SIZE:  // якщо вікно змінює розмір - розтягуємо список
            MoveWindow(hListBox, 0, UI_HEADER_HEIGHT, LOWORD(lParam), HIWORD(lParam) - UI_HEADER_HEIGHT - UI_BOTTOM_HEIGHT, TRUE);
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
            if (LOWORD(wParam) == VK_ESCAPE) {  // Esc - закрити меню
                ShowWindow(hwnd, SW_HIDE); return -2; 
            }
            
            if (LOWORD(wParam) == 'P' || LOWORD(wParam) == 'p') {  // стрибок до запінених клавішею 'P'
                if (firstPinnedListIdx != -1) {
                    SendMessage(hListBox, LB_SETCURSEL, firstPinnedListIdx, 0);
                    // прокручуємо на перший запінений елемент
                    SendMessage(hListBox, LB_SETTOPINDEX, firstPinnedListIdx, 0); 
                }
                return -2; // кажемо системі, що ми самі обробили натискання
            }

            if (LOWORD(wParam) == VK_DELETE) {  // Delete - видалити запис
                int sel = SendMessage(hListBox, LB_GETCURSEL, 0, 0);
                if (sel >= 0) {
                    LRESULT itemData = SendMessage(hListBox, LB_GETITEMDATA, sel, 0);
                    if (itemData != LB_ERR) {
                        bool isPinned = (itemData >> 8) & 1;
                        uint8_t realIdx = itemData & 0xFF;
                        
                        RemoveByRealIndex(realIdx, isPinned); 
                        UpdateListBox();
                        
                        int count = SendMessage(hListBox, LB_GETCOUNT, 0, 0);
                        if (count > 0) SendMessage(hListBox, LB_SETCURSEL, sel >= count ? count - 1 : sel, 0); 
                    }
                }
                return -2;
            }
            
            if (LOWORD(wParam) == VK_DOWN || LOWORD(wParam) == VK_UP) {
                int curSel = SendMessage(hListBox, LB_GETCURSEL, 0, 0);
                int count = SendMessage(hListBox, LB_GETCOUNT, 0, 0);
                if (count > 0) {
                    if (LOWORD(wParam) == VK_DOWN) {
                        curSel = (curSel + 1) % count;
                    } else if (LOWORD(wParam) == VK_UP) {
                        curSel = (curSel - 1 + count) % count;
                    }
                    SendMessage(hListBox, LB_SETCURSEL, curSel, 0);
                    return -2; 
                }
            }
            return -1; 

        case WM_ACTIVATE: // якщо юзер клікає поза вікном — ховаємо його
            if (LOWORD(wParam) == WA_INACTIVE) ShowWindow(hwnd, SW_HIDE); 
            break;

        case WM_CLOSE: // явне руйнування вікна
            DestroyWindow(hwnd);
            return 0;

        case WM_DESTROY: 
            ManageTrayIcon(hwnd, NIM_DELETE); // видаляємо іконку з трею при закритті
            RemoveClipboardFormatListener(hwnd); 
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
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        // якщо утиліта вже працює — знаходимо її вікно і відправляємо команду на закриття
        HWND hExistingWnd = FindWindowW(L"CustomClipboardMenu", NULL);
        if (hExistingWnd) {
            PostMessage(hExistingWnd, WM_CLOSE, 0, 0);
        }
        CloseHandle(hMutex);
        return 0; // завершуємо цей екземпляр
    }

    InitMaps(); 
    
    LoadHistory(); 

    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    if (hUser32) {
        typedef BOOL(WINAPI *SetProcessDPIAwareFunc)();
        SetProcessDPIAwareFunc setDpiAware = (SetProcessDPIAwareFunc)GetProcAddress(hUser32, "SetProcessDPIAware");
        if (setDpiAware) setDpiAware();
    }

    hDarkBrush = CreateSolidBrush(RGB(25, 25, 25)); 
    HDC hdc = GetDC(NULL);
    int dpiY = GetDeviceCaps(hdc, LOGPIXELSY);
    ReleaseDC(NULL, hdc);
    
    int fontSize = -MulDiv(13, dpiY, 96); 
    g_ItemHeight = MulDiv(UI_ITEM_HEIGHT, dpiY, 96);  
    hFont = CreateFontW(fontSize, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 
                        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, 
                        DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = WndProc; 
    wc.hInstance = hInstance;
    
    // намагаємось завантажити іконку з exe для вікна, або беремо стандартну
    wc.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_APPICON));
    if (!wc.hIcon) wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    
    wc.lpszClassName = L"CustomClipboardMenu";
    wc.hbrBackground = hDarkBrush; 
    RegisterClass(&wc);

    hMainWindow = CreateWindowEx(WS_EX_TOOLWINDOW | WS_EX_TOPMOST, L"CustomClipboardMenu", L"Буфер обміну",
        WS_POPUP, 0, 0, UI_WIN_WIDTH, UI_WIN_HEIGHT, NULL, NULL, hInstance, NULL);

    g_hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, hInstance, 0);

    MSG msg = { 0 };
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    if (g_hKeyboardHook) UnhookWindowsHookEx(g_hKeyboardHook);
    DeleteObject(hDarkBrush); DeleteObject(hFont);
    
    // звільнення мутексу при виході
    CloseHandle(hMutex);
    
    return 0;
}
