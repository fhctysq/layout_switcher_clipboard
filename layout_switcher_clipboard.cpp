#define UNICODE
#define _UNICODE

// Кажемо Windows використовувати сучасний дизайн для списку і кнопок (візуальний стиль)
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#pragma comment(lib, "uxtheme.lib") 

#include <windows.h>
#include <windowsx.h> 
#include <uxtheme.h> 
#include <strsafe.h> 
#include <shellapi.h> // Для роботи з піктограмою в системному лотку (треї)

// ==========================================
// --- ВІЗУАЛЬНІ НАЛАШТУВАННЯ ІНТЕРФЕЙСУ ---
// ==========================================
#define UI_WIN_WIDTH 560        // Ширина головного вікна-меню
#define UI_WIN_HEIGHT 704       // Висота головного вікна
#define UI_ITEM_HEIGHT 90       // Висота однієї "картки" з текстом у списку
#define UI_ITEM_GAP 8           // Відстань між картками
#define UI_CORNER_RADIUS 18     // Наскільки круглими будуть кути вікна та карток
#define UI_PREVIEW_LENGTH 168   // Скільки перших символів тексту показувати у прев'ю
#define UI_HEADER_HEIGHT 32     // Висота верхньої "шапки" (за яку можна тягати вікно)
#define UI_BOTTOM_HEIGHT 32     // Висота нижньої смужки

// ==========================================
// --- НАЛАШТУВАННЯ ТРЕЮ ТА ІКОНКИ ---
// ==========================================
#define WM_TRAYICON (WM_APP + 2) // Кастомне повідомлення для обробки кліків у треї
#define IDI_APPICON 101          // ID іконки в ресурсах (.rc файл)

// ==========================================
// --- НАЛАШТУВАННЯ ПАМ'ЯТІ ТА БЕЗПЕКИ ---
// ==========================================
#define HEAP_SIZE_LIMIT (1024 * 1024)     // Максимум 1 МБ оперативної пам'яті для текстів
#define LARGE_TEXT_THRESHOLD (256 * 1024) // Якщо скопіювали більше 256 КБ за раз — скидаємо у файл
#define MAX_HISTORY_ITEMS 512             // Скільки записів пам'ятати в історії

// УВАГА: Це лише ОБФУСКАЦІЯ (XOR), а не криптографічне шифрування
#define OBFUSCATION_KEY L"MySecretKey2026"

HANDLE hMemHeap = NULL;               // "Пісочниця" пам'яті на 1 МБ (захищає від витоків пам'яті)
wchar_t* history[MAX_HISTORY_ITEMS];  // Масив, що зберігає скопійовані тексти
int historyCount = 0;                 // Поточна кількість збережених текстів

HWND hMainWindow = NULL;              // Головне вікно програми
HWND hListBox = NULL;                 // Елемент списку, де відображається історія

bool ignoreClipboardUpdate = false;   // Запобіжник: якщо true, програма ігнорує копіювання (бо робить його сама)

// --- Елементи для малювання (кольори, шрифти) ---
HBRUSH hDarkBrush = NULL; 
HFONT hFont = NULL;       
int g_ItemHeight = UI_ITEM_HEIGHT; 

// --- Бекапи та технічні змінні ---
wchar_t* g_SysClipboardBackup = NULL; // Тимчасове сховище для справжнього буфера обміну ОС
wchar_t* lastAltCCopy = NULL;         // Останній текст, скопійований саме через Alt+C
WNDPROC OldListBoxProc;               // Попередня функція обробки списку (для підміни кліків мишею)

HHOOK g_hKeyboardHook = NULL;         // Змінна для "шпигуна" за клавіатурою (глобальний хук)
#define MSG_PROCESS_HOTKEY (WM_APP + 1) // Кастомне повідомлення, щоб сказати вікну "натиснуто нашу комбінацію"

// ==========================================
// --- СТРУКТУРИ ТА ПЕРЕЛІКИ (ENUMS) ---
// ==========================================
enum class TransformMode { 
    Layout = 0,         // Зміна розкладки (Pause)
    Case = 1,           // Регістр (Alt+Pause)
    StrikeSlanted = 2,  // Скісне закреслення (Alt+Numpad /)
    StrikeStraight = 3  // Пряме закреслення (Alt+Numpad -)
};

enum class HotkeyCmd { 
    Layout = 1, Copy = 2, Paste = 3, MenuDown = 4, Cut = 6, 
    Undo = 7, MenuUp = 8, Case = 9, SilentCopyAll = 10, 
    StrikeSlanted = 11, StrikeStraight = 12 
};

// ==========================================
// --- СЛОВНИКИ ДЛЯ ЗМІНИ РОЗКЛАДКИ ---
// ==========================================
wchar_t eng_to_ukr[65535]; 
wchar_t ukr_to_eng[65535]; 

// Ініціалізація пар символів для перекладу англійська <-> українська
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

// ==========================================
// --- ОБФУСКАЦІЯ ТА ФАЙЛИ ---
// ==========================================
// Стрим-шифр RC4. Захищає збережені тексти на диску від простого перегляду.
void XorBuffer(BYTE* buffer, DWORD size) {
    BYTE s[256];
    DWORD keyLen = lstrlenW(OBFUSCATION_KEY) * sizeof(wchar_t);
    BYTE* keyBytes = (BYTE*)OBFUSCATION_KEY;

    for (int i = 0; i < 256; i++) s[i] = i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + s[i] + keyBytes[i % keyLen]) % 256;
        BYTE temp = s[i]; s[i] = s[j]; s[j] = temp;
    }

    int i = 0; j = 0;
    for (DWORD k = 0; k < size; k++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        BYTE temp = s[i]; s[i] = s[j]; s[j] = temp;
        buffer[k] ^= s[(s[i] + s[j]) % 256];
    }
}

// ==========================================
// --- СИМУЛЯЦІЯ НАТИСКАНЬ ---
// ==========================================
// Функція змушує систему думати, що ми натиснули комбінацію (напр. Ctrl+C)
void SendKeyCombo(WORD modifier, WORD key) {
    INPUT inputs[16] = {}; 
    int c = 0;
    
    // Перевіряємо, чи фізично затиснуті клавіші користувачем
    bool lAltHeld = (GetAsyncKeyState(VK_LMENU) & 0x8000) != 0;
    bool lCtrlHeld = (GetAsyncKeyState(VK_LCONTROL) & 0x8000) != 0;
    bool rCtrlHeld = (GetAsyncKeyState(VK_RCONTROL) & 0x8000) != 0;
    
    // Якщо користувач тримає Alt, відпускаємо його програмно.
    if (lAltHeld) { inputs[c].type = INPUT_KEYBOARD; inputs[c].ki.wVk = VK_LMENU; inputs[c].ki.dwFlags = KEYEVENTF_KEYUP; c++; }
    
    // Натискаємо модифікатор (напр. Ctrl) і саму клавішу (напр. V), потім відпускаємо обох
    inputs[c].type = INPUT_KEYBOARD; inputs[c].ki.wVk = modifier; c++;
    inputs[c].type = INPUT_KEYBOARD; inputs[c].ki.wVk = key; c++;
    inputs[c].type = INPUT_KEYBOARD; inputs[c].ki.wVk = key; inputs[c].ki.dwFlags = KEYEVENTF_KEYUP; c++;
    inputs[c].type = INPUT_KEYBOARD; inputs[c].ki.wVk = modifier; inputs[c].ki.dwFlags = KEYEVENTF_KEYUP; c++;
    
    if (lAltHeld) { 
        // Повертаємо Лівий Alt назад, щоб користувач міг продовжувати тримати його
        inputs[c].type = INPUT_KEYBOARD; inputs[c].ki.wVk = VK_LMENU; c++; 
        
        // ОБХІД: Клікаємо "пустим" Ctrl, щоб меню вікон (File, Edit...) не фокусувалося після відпускання Alt
        inputs[c].type = INPUT_KEYBOARD; inputs[c].ki.wVk = VK_LCONTROL; c++;
        inputs[c].type = INPUT_KEYBOARD; inputs[c].ki.wVk = VK_LCONTROL; inputs[c].ki.dwFlags = KEYEVENTF_KEYUP; c++;
    }

    // ВАЖЛИВО: Якщо ми імітували відпускання Ctrl, але фізично він затиснутий, відновлюємо стан для ОС
    if (modifier == VK_CONTROL) {
        if (lCtrlHeld) { inputs[c].type = INPUT_KEYBOARD; inputs[c].ki.wVk = VK_LCONTROL; c++; }
        if (rCtrlHeld) { inputs[c].type = INPUT_KEYBOARD; inputs[c].ki.wVk = VK_RCONTROL; c++; }
    }
    
    SendInput(c, inputs, sizeof(INPUT)); 
}

// ==========================================
// --- ГЛОБАЛЬНИЙ ХУК КЛАВІАТУРИ ---
// ==========================================
// Хелпер-фікс для відміни фокусування меню після натискання Alt
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

        // --- ВІДСТЕЖЕННЯ CTRL+A ---
        static bool ctrlA_handled = false;
        if (pKeyBoard->vkCode == 'A') {
            if (isKeyDown) {
                if (isCtrlPressed && !isLeftAltPressed && !isRightAltPressed) {
                    if (!ctrlA_handled) {
                        ctrlA_handled = true;
                        // Сигналізуємо системі: був натиснутий Ctrl+A.
                        PostMessage(hMainWindow, MSG_PROCESS_HOTKEY, static_cast<WPARAM>(HotkeyCmd::SilentCopyAll), 0);
                    }
                }
            } else if (isKeyUp) {
                ctrlA_handled = false; 
            }
        }

        if (isKeyDown) {
            if (pKeyBoard->vkCode == VK_PAUSE) {
                if (isRightAltPressed) return CallNextHookEx(g_hKeyboardHook, nCode, wParam, lParam);
                
                if (isLeftAltPressed) { 
                    CancelWindowsMenuFocus(); 
                    PostMessage(hMainWindow, MSG_PROCESS_HOTKEY, static_cast<WPARAM>(HotkeyCmd::Case), 0); 
                } 
                else PostMessage(hMainWindow, MSG_PROCESS_HOTKEY, static_cast<WPARAM>(HotkeyCmd::Layout), 0);                  
                return 1;
            }
            
            if (isLeftAltPressed && !isRightAltPressed) { 
                if (pKeyBoard->vkCode == 'C') { CancelWindowsMenuFocus(); PostMessage(hMainWindow, MSG_PROCESS_HOTKEY, static_cast<WPARAM>(HotkeyCmd::Copy), 0); return 1; }
                if (pKeyBoard->vkCode == 'V') { CancelWindowsMenuFocus(); PostMessage(hMainWindow, MSG_PROCESS_HOTKEY, static_cast<WPARAM>(HotkeyCmd::Paste), 0); return 1; }
                if (pKeyBoard->vkCode == 'B') { CancelWindowsMenuFocus(); PostMessage(hMainWindow, MSG_PROCESS_HOTKEY, static_cast<WPARAM>(HotkeyCmd::MenuDown), 0); return 1; }
                if (pKeyBoard->vkCode == 'X') { CancelWindowsMenuFocus(); PostMessage(hMainWindow, MSG_PROCESS_HOTKEY, static_cast<WPARAM>(HotkeyCmd::Cut), 0); return 1; } 
                if (pKeyBoard->vkCode == 'Z') { CancelWindowsMenuFocus(); PostMessage(hMainWindow, MSG_PROCESS_HOTKEY, static_cast<WPARAM>(HotkeyCmd::Undo), 0); return 1; } 
                if (pKeyBoard->vkCode == 'N') { CancelWindowsMenuFocus(); PostMessage(hMainWindow, MSG_PROCESS_HOTKEY, static_cast<WPARAM>(HotkeyCmd::MenuUp), 0); return 1; } 
                
                // Вихід з програми (Alt+Q)
                if (pKeyBoard->vkCode == 'Q') { 
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

// ==========================================
// --- РОБОТА З ФАЙЛАМИ (ДЛЯ ВЕЛИКИХ ТЕКСТІВ) ---
// ==========================================
// Функція розпізнавання: чи збережений текст є вказівником на файл (якщо він надто великий)
bool IsLargeFile(const wchar_t* text) {
    return (text && wcsncmp(text, L"[LARGEFILE]", 11) == 0);
}

// Зберігає гігантський текст у файл, шифрує його та повертає "плейсхолдер"
bool SaveLargeText(const wchar_t* text, wchar_t* outPlaceholder) {
    CreateDirectoryW(L"ClipboardData", NULL); 
    static int counter = 0;
    wchar_t filepath[MAX_PATH];
    
    StringCchPrintfW(filepath, MAX_PATH, L"ClipboardData\\item_%u_%d.txt", GetTickCount(), ++counter);

    HANDLE hFile = CreateFileW(filepath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD bytesSize = lstrlenW(text) * sizeof(wchar_t);
        BYTE* encBuffer = (BYTE*)HeapAlloc(hMemHeap, 0, bytesSize);
        if (encBuffer) {
            memcpy(encBuffer, text, bytesSize);
            XorBuffer(encBuffer, bytesSize); 
            DWORD written;
            WriteFile(hFile, encBuffer, bytesSize, &written, NULL);
            HeapFree(hMemHeap, 0, encBuffer);
        }
        CloseHandle(hFile);

        wchar_t preview[UI_PREVIEW_LENGTH + 1] = {0};
        wcsncpy_s(preview, UI_PREVIEW_LENGTH + 1, text, UI_PREVIEW_LENGTH);
        preview[UI_PREVIEW_LENGTH] = L'\0'; 
        for (int i = 0; i < UI_PREVIEW_LENGTH && preview[i]; ++i) {
            if (preview[i] == L'\r' || preview[i] == L'\n') preview[i] = L' ';
        }

        StringCchPrintfW(outPlaceholder, MAX_PATH + UI_PREVIEW_LENGTH + 50, L"[LARGEFILE]%s|%s", filepath, preview);
        return true;
    }
    return false;
}

// Завантажує і розшифровує великий текст із файлу, якщо користувач вирішив його вставити
wchar_t* LoadLargeText(const wchar_t* placeholder) {
    const wchar_t* pipe = wcschr(placeholder, L'|');
    if (!pipe) return NULL;
    int pathLen = pipe - (placeholder + 11);
    wchar_t filepath[MAX_PATH] = {0};
    if (pathLen >= MAX_PATH) pathLen = MAX_PATH - 1; 
    wcsncpy_s(filepath, MAX_PATH, placeholder + 11, pathLen);
    filepath[pathLen] = L'\0'; 

    HANDLE hFile = CreateFileW(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD size = GetFileSize(hFile, NULL);
        wchar_t* text = (wchar_t*)HeapAlloc(hMemHeap, 0, size + sizeof(wchar_t));
        if (text) {
            DWORD read;
            ReadFile(hFile, text, size, &read, NULL);
            XorBuffer((BYTE*)text, read); 
            text[read / sizeof(wchar_t)] = L'\0';
            CloseHandle(hFile);
            return text;
        }
        CloseHandle(hFile);
    }
    
    wchar_t* fallback = (wchar_t*)HeapAlloc(hMemHeap, 0, 128 * sizeof(wchar_t));
    if (fallback) StringCchCopyW(fallback, 128, L"[ПОМИЛКА] Файл з великим текстом не знайдено.");
    return fallback;
}

// Зберігає історію дрібних текстів у єдиний файл
void SaveHistory() {
    HANDLE hFile = CreateFileW(L"custom_clipboard.bin", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hFile, &historyCount, sizeof(int), &written, NULL); 
        for (int i = 0; i < historyCount; i++) {
            int len = lstrlenW(history[i]);
            WriteFile(hFile, &len, sizeof(int), &written, NULL); 
            
            DWORD bytesSize = len * sizeof(wchar_t);
            BYTE* encBuffer = (BYTE*)HeapAlloc(hMemHeap, 0, bytesSize);
            if (encBuffer) {
                memcpy(encBuffer, history[i], bytesSize);
                XorBuffer(encBuffer, bytesSize); 
                WriteFile(hFile, encBuffer, bytesSize, &written, NULL);
                HeapFree(hMemHeap, 0, encBuffer);
            }
        }
        CloseHandle(hFile);
    }
}

// ==========================================
// --- УПРАВЛІННЯ ІСТОРІЄЮ ТА ЗОМБІ-ЗАПИСАМИ ---
// ==========================================
// Якщо пам'яті мало — скидає найстаріші записи у файли
bool EvictOldestToDisk() {
    for (int i = historyCount - 1; i >= 0; i--) {
        if (!IsLargeFile(history[i])) { 
            wchar_t placeholder[MAX_PATH + UI_PREVIEW_LENGTH + 50];
            if (SaveLargeText(history[i], placeholder)) { 
                size_t pBytes = (lstrlenW(placeholder) + 1) * sizeof(wchar_t);
                
                HeapFree(hMemHeap, 0, history[i]); 
                wchar_t* newPtr = (wchar_t*)HeapAlloc(hMemHeap, 0, pBytes); 
                if (newPtr) {
                    StringCchCopyW(newPtr, pBytes / sizeof(wchar_t), placeholder);
                    history[i] = newPtr; 
                    SaveHistory();       
                    return true;
                } else {
                    for (int j = i; j < historyCount - 1; ++j) history[j] = history[j + 1];
                    historyCount--;
                    return true;
                }
            }
        }
    }
    return false; 
}

// Видаляє конкретний запис з історії (і перевіряє, чи він не був записаний як Alt+C)
void RemoveFromHistory(int index) {
    if (index < 0 || index >= historyCount) return;
    
    // --- ПЕРЕВІРКА НА ЗОМБІ (Alt+V логіка) ---
    // Якщо користувач видаляє запис, який також є останнім для Alt+C, ми очищуємо Alt+C
    if (lastAltCCopy) {
        bool isZombie = false;
        if (!IsLargeFile(history[index])) {
            if (lstrcmpW(history[index], lastAltCCopy) == 0) isZombie = true;
        } else {
            wchar_t* loaded = LoadLargeText(history[index]);
            if (loaded) {
                if (lstrcmpW(loaded, lastAltCCopy) == 0) isZombie = true;
                HeapFree(hMemHeap, 0, loaded);
            }
        }
        if (isZombie) {
            HeapFree(hMemHeap, 0, lastAltCCopy);
            lastAltCCopy = NULL; // Тепер Alt+V перейде на fallback (найновіший запис)
        }
    }
    // -----------------------------------------

    if (IsLargeFile(history[index])) {
        const wchar_t* pipe = wcschr(history[index], L'|');
        if (pipe) {
            int pathLen = pipe - (history[index] + 11);
            wchar_t filepath[MAX_PATH] = {0};
            if (pathLen >= MAX_PATH) pathLen = MAX_PATH - 1;  
            wcsncpy_s(filepath, MAX_PATH, history[index] + 11, pathLen);
            filepath[pathLen] = L'\0';  
            DeleteFileW(filepath);
        }
    }
    
    HeapFree(hMemHeap, 0, history[index]);
    for (int i = index; i < historyCount - 1; ++i) history[i] = history[i + 1];
    historyCount--;
    SaveHistory();
}

void AddToHistory(const wchar_t* text) {
    size_t bytes = (lstrlenW(text) + 1) * sizeof(wchar_t);
    size_t cch = bytes / sizeof(wchar_t);
    wchar_t* newEntry = NULL;

    if (bytes > LARGE_TEXT_THRESHOLD) {
        wchar_t placeholder[MAX_PATH + UI_PREVIEW_LENGTH + 50];
        if (SaveLargeText(text, placeholder)) {
            size_t pBytes = (lstrlenW(placeholder) + 1) * sizeof(wchar_t);
            while (!(newEntry = (wchar_t*)HeapAlloc(hMemHeap, 0, pBytes))) {
                if (!EvictOldestToDisk()) { 
                    if (historyCount > 0) RemoveFromHistory(historyCount - 1); 
                    else return; 
                }
            }
            StringCchCopyW(newEntry, pBytes / sizeof(wchar_t), placeholder);
        }
    } 
    if (!newEntry) {
        while (!(newEntry = (wchar_t*)HeapAlloc(hMemHeap, 0, bytes))) {
            if (!EvictOldestToDisk()) {
                if (historyCount > 0) RemoveFromHistory(historyCount - 1);
                else return;
            }
        }
        StringCchCopyW(newEntry, cch, text);
    }
    if (!newEntry) return;

    if (historyCount > 0 && lstrcmpW(history[0], newEntry) == 0) {
        HeapFree(hMemHeap, 0, newEntry);
        return;
    }

    if (historyCount == MAX_HISTORY_ITEMS) RemoveFromHistory(historyCount - 1); 

    for (int i = historyCount; i > 0; --i) history[i] = history[i - 1];
    history[0] = newEntry; 
    historyCount++;
    SaveHistory(); 
}

void LoadHistory() {
    HANDLE hFile = CreateFileW(L"custom_clipboard.bin", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD read;
        int count = 0;
        if (ReadFile(hFile, &count, sizeof(int), &read, NULL) && count > 0) {
            if (count > MAX_HISTORY_ITEMS) count = MAX_HISTORY_ITEMS;
            for (int i = 0; i < count; i++) {
                int len = 0;
                if (ReadFile(hFile, &len, sizeof(int), &read, NULL) && len > 0) {
                    size_t bytes = (len + 1) * sizeof(wchar_t);
                    
                    wchar_t* text = (wchar_t*)HeapAlloc(hMemHeap, 0, bytes);
                    while (!text && historyCount > 0) {
                        EvictOldestToDisk();
                        text = (wchar_t*)HeapAlloc(hMemHeap, 0, bytes);
                    }
                    
                    if (text) {
                        ReadFile(hFile, text, len * sizeof(wchar_t), &read, NULL);
                        XorBuffer((BYTE*)text, len * sizeof(wchar_t)); 
                        text[len] = L'\0';
                        history[historyCount++] = text;
                    } else {
                        SetFilePointer(hFile, len * sizeof(wchar_t), NULL, FILE_CURRENT);
                    }
                }
            }
        }
        CloseHandle(hFile);
    }
}

// ==========================================
// --- СЕПАРАЦІЯ БУФЕРА ТА ОПЕРАЦІЇ ---
// ==========================================
// Робить бекап справжнього буфера обміну ОС перед нашими "хаками"
void BackupSysClipboard() {
    if (g_SysClipboardBackup) { HeapFree(hMemHeap, 0, g_SysClipboardBackup); g_SysClipboardBackup = NULL; }
    if (OpenClipboard(NULL)) {
        HANDLE hData = GetClipboardData(CF_UNICODETEXT);
        if (hData) {
            wchar_t* pText = static_cast<wchar_t*>(GlobalLock(hData));
            if (pText) {
                size_t cch = lstrlenW(pText) + 1;
                g_SysClipboardBackup = (wchar_t*)HeapAlloc(hMemHeap, 0, cch * sizeof(wchar_t));
                if (g_SysClipboardBackup) StringCchCopyW(g_SysClipboardBackup, cch, pText);
                GlobalUnlock(hData);
            }
        }
        CloseClipboard();
    }
}

// Відновлює справжній буфер обміну ОС після "хаків"
void RestoreSysClipboard() {
    if (OpenClipboard(NULL)) {
        EmptyClipboard();
        if (g_SysClipboardBackup) {
            size_t bytes = (lstrlenW(g_SysClipboardBackup) + 1) * sizeof(wchar_t);
            HGLOBAL hData = GlobalAlloc(GMEM_MOVEABLE, bytes); 
            if (hData) {
                wchar_t* pDest = static_cast<wchar_t*>(GlobalLock(hData));
                StringCchCopyW(pDest, bytes / sizeof(wchar_t), g_SysClipboardBackup);
                GlobalUnlock(hData);
                SetClipboardData(CF_UNICODETEXT, hData);
            }
        }
        CloseClipboard();
    }
    if (g_SysClipboardBackup) { HeapFree(hMemHeap, 0, g_SysClipboardBackup); g_SysClipboardBackup = NULL; }
}

void ClearPendingClipboardUpdates() {
    MSG msg;
    while (PeekMessage(&msg, hMainWindow, WM_CLIPBOARDUPDATE, WM_CLIPBOARDUPDATE, PM_REMOVE)) {}
}

// Кастомне копіювання/вирізання (наприклад, через Alt+C). 
// setAsAltC = false використовується для тихого фонового копіювання (Ctrl+A), щоб не затерти справжній Alt+C
void CustomCopyOrCut(WORD vkCode, bool setAsAltC = true) { 
    ignoreClipboardUpdate = true; 
    BackupSysClipboard();         

    DWORD startSeq = GetClipboardSequenceNumber(); 
    SendKeyCombo(VK_CONTROL, vkCode); 
    
    // Чекаємо, поки програма-донор віддасть текст у буфер обміну
    bool updated = false;
    for (int i = 0; i < 16; ++i) {
        Sleep(20);
        if (GetClipboardSequenceNumber() != startSeq) { updated = true; break; }
    }
    Sleep(30); 
    
    if (updated && OpenClipboard(NULL)) {
        HANDLE hData = GetClipboardData(CF_UNICODETEXT);
        if (hData) {
            wchar_t* pText = static_cast<wchar_t*>(GlobalLock(hData));
            if (pText) {
                AddToHistory(pText); 
                
                // Зберігаємо як запис для Alt+V ТІЛЬКИ якщо це не фонове Ctrl+A
                if (setAsAltC) {
                    if (lastAltCCopy) HeapFree(hMemHeap, 0, lastAltCCopy);
                    size_t cch = lstrlenW(pText) + 1;
                    lastAltCCopy = (wchar_t*)HeapAlloc(hMemHeap, 0, cch * sizeof(wchar_t));
                    if (lastAltCCopy) StringCchCopyW(lastAltCCopy, cch, pText);
                }

                GlobalUnlock(hData);
            }
        }
        CloseClipboard();
    }

    RestoreSysClipboard(); 
    ClearPendingClipboardUpdates();
    ignoreClipboardUpdate = false;
}

// Вставка останнього скопійованого через Alt+C тексту (або фолбек)
void PasteLastAltC() { 
    if (!lastAltCCopy) return;
    
    ignoreClipboardUpdate = true;
    BackupSysClipboard(); 

    if (OpenClipboard(NULL)) {
        EmptyClipboard();
        size_t cch = lstrlenW(lastAltCCopy) + 1;
        HGLOBAL hData = GlobalAlloc(GMEM_MOVEABLE, cch * sizeof(wchar_t));
        if (hData) {
            wchar_t* pDest = static_cast<wchar_t*>(GlobalLock(hData));
            StringCchCopyW(pDest, cch, lastAltCCopy);
            GlobalUnlock(hData);
            SetClipboardData(CF_UNICODETEXT, hData);
        }
        CloseClipboard();
        
        SendKeyCombo(VK_CONTROL, 0x56); // Імітація натискання Ctrl+V
        Sleep(50); 
    }

    RestoreSysClipboard(); 
    ClearPendingClipboardUpdates();
    ignoreClipboardUpdate = false;
}

// Вставка конкретного тексту з історії (вибір через віконце)
void PasteFromHistory(int index) {
    if (index < 0 || index >= historyCount) return;
    
    ShowWindow(hMainWindow, SW_HIDE); 
    ignoreClipboardUpdate = true; 
    BackupSysClipboard();

    wchar_t* textToPaste = history[index];
    bool isLarge = IsLargeFile(textToPaste);
    
    if (isLarge) textToPaste = LoadLargeText(textToPaste);

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
        Sleep(50);
    }
    
    if (isLarge && textToPaste) HeapFree(hMemHeap, 0, textToPaste); 
    RestoreSysClipboard(); 
    ClearPendingClipboardUpdates();
    ignoreClipboardUpdate = false;

    // Піднімаємо використаний текст нагору списку (щоб він був найновішим)
    if (index != 0) {
        wchar_t* temp = history[index];
        for (int i = index; i > 0; --i) history[i] = history[i - 1];
        history[0] = temp;
        SaveHistory();
    }
}

// Головна "магія": зміна розкладки, регістру або закреслення тексту прямо на льоту
void TransformClipboardText(TransformMode mode) {
    ignoreClipboardUpdate = true; 
    BackupSysClipboard();

    DWORD currentSeq = GetClipboardSequenceNumber();
    SendKeyCombo(VK_CONTROL, 0x43);  
    
    bool clipboardUpdated = false;
    for (int i = 0; i < 15; ++i) {
        Sleep(20);
        if (GetClipboardSequenceNumber() != currentSeq) { clipboardUpdated = true; break; }
    }
    
    if (clipboardUpdated && OpenClipboard(NULL)) {
        HANDLE hData = GetClipboardData(CF_UNICODETEXT);
        if (hData) {
            wchar_t* pText = static_cast<wchar_t*>(GlobalLock(hData));
            if (pText) {
                size_t len = lstrlenW(pText);
                size_t size = (mode == TransformMode::StrikeSlanted || mode == TransformMode::StrikeStraight) 
                              ? (len * 2 + 1) * sizeof(wchar_t) 
                              : (len + 1) * sizeof(wchar_t);
                HGLOBAL hNewData = GlobalAlloc(GMEM_MOVEABLE, size);
                
                if (hNewData) {
                    wchar_t* pNewText = static_cast<wchar_t*>(GlobalLock(hNewData));
                    bool changed = false;

                    // ЗАКРЕСЛЕННЯ ТЕКСТУ
                    if (mode == TransformMode::StrikeSlanted || mode == TransformMode::StrikeStraight) {
                        wchar_t strikeChar = (mode == TransformMode::StrikeSlanted) ? L'\x0337' : L'\x0336';
                        size_t j = 0;
                        for (size_t i = 0; i < len; ++i) {
                            pNewText[j++] = pText[i];
                            bool isHighSurrogate = (pText[i] >= 0xD800 && pText[i] <= 0xDBFF);
                            if (!isHighSurrogate && pText[i] != L'\r' && pText[i] != L'\n' && pText[i] != L'\t') {
                                pNewText[j++] = strikeChar; 
                                changed = true;
                            }
                        }
                        pNewText[j] = L'\0';
                    } 
                    // ЗМІНА РОЗКЛАДКИ ТА РЕГІСТРУ
                    else {
                        for (size_t i = 0; i < len; ++i) {
                            wchar_t ch = pText[i];
                            if (mode == TransformMode::Layout) {
                                if (eng_to_ukr[ch]) { pNewText[i] = eng_to_ukr[ch]; changed = true; }
                                else if (ukr_to_eng[ch]) { pNewText[i] = ukr_to_eng[ch]; changed = true; }
                                else { pNewText[i] = ch; }
                            } else if (mode == TransformMode::Case) {
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
                                else { pNewText[i] = ch; }
                            }
                        }
                        pNewText[len] = L'\0';
                    }

                    GlobalUnlock(hNewData);

                    // Якщо були зміни — вставляємо текст назад у програму
                    if (changed) {
                        EmptyClipboard();
                        SetClipboardData(CF_UNICODETEXT, hNewData);
                        GlobalUnlock(hData);
                        CloseClipboard();

                        SendKeyCombo(VK_CONTROL, 0x56); 
                        Sleep(50); 
                        goto cleanup; 
                    } else { GlobalFree(hNewData); }
                }
            }
            GlobalUnlock(hData);
        }
        CloseClipboard();
    }

cleanup:
    RestoreSysClipboard();
    ClearPendingClipboardUpdates();
    ignoreClipboardUpdate = false;
}

// ==========================================
// --- ІНТЕРФЕЙС ТА МАЛЮВАННЯ (ГРАФІКА) ---
// ==========================================
// Оновлює список текстів у вікні UI
void UpdateListBox() {
    SendMessage(hListBox, LB_RESETCONTENT, 0, 0); 
    wchar_t display[UI_PREVIEW_LENGTH + 5]; 
    
    for (int i = 0; i < historyCount; ++i) {
        const wchar_t* textPtr = history[i];
        
        if (IsLargeFile(textPtr)) {
            const wchar_t* pipe = wcschr(textPtr, L'|');
            if (pipe) textPtr = pipe + 1; 
        }

        int j = 0;
        for (int k = 0; textPtr[k] != L'\0' && j < UI_PREVIEW_LENGTH; k++) {
            if (textPtr[k] == L'\r') continue; // Ігноруємо "каретки" 
            if (textPtr[k] == L'\n') { display[j++] = L' '; continue; } // Заміняємо переноси на пробіли
            display[j++] = textPtr[k];
        }
        if (lstrlenW(textPtr) > UI_PREVIEW_LENGTH && j <= UI_PREVIEW_LENGTH) { 
            StringCchCopyW(display + j, (UI_PREVIEW_LENGTH + 5) - j, L"..."); 
            j += 3; 
        }
        display[j] = L'\0';
        SendMessageW(hListBox, LB_ADDSTRING, 0, (LPARAM)display); 
    }
}

// Відображає вікно історії біля місця, де користувач працює
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
    
    // Намагаємось вивести вікно поруч з активним додатком, або на позиції курсору
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

// Хак для перехоплення кліків мишею по списку (Listbox)
LRESULT CALLBACK ListBoxSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_RBUTTONDOWN) {
        DWORD itemInfo = SendMessage(hwnd, LB_ITEMFROMPOINT, 0, lParam);
        if (HIWORD(itemInfo) == 0) { 
            SendMessage(hwnd, LB_SETCURSEL, LOWORD(itemInfo), 0); // Тільки виділяємо (щоб можна було видалити)
        }
        return 0; 
    }
    if (msg == WM_LBUTTONUP) { 
        LRESULT res = CallWindowProc(OldListBoxProc, hwnd, msg, wParam, lParam);
        DWORD itemInfo = SendMessage(hwnd, LB_ITEMFROMPOINT, 0, lParam);
        if (HIWORD(itemInfo) == 0) { 
            PostMessage(GetParent(hwnd), WM_COMMAND, MAKEWPARAM(1, 1000), (LPARAM)hwnd); // Вставляємо при лівому кліку
        }
        return res;
    }
    return CallWindowProc(OldListBoxProc, hwnd, msg, wParam, lParam);
}

// Функція для керування іконкою в системному лотку
void ManageTrayIcon(HWND hwnd, DWORD dwMessage) {
    NOTIFYICONDATAW nid = { sizeof(nid) };
    nid.hWnd = hwnd;
    nid.uID = 1;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    
    // Намагаємось завантажити іконку з exe, якщо не знайдено — беремо стандартну
    nid.hIcon = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_APPICON));
    if (!nid.hIcon) nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    
    StringCchCopyW(nid.szTip, ARRAYSIZE(nid.szTip), L"Кастомний Буфер Обміну");
    Shell_NotifyIconW(dwMessage, &nid);
}

// ==========================================
// --- ГОЛОВНИЙ ОБРОБНИК ВІКНА ---
// ==========================================
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: 
            ManageTrayIcon(hwnd, NIM_ADD); // Реєструємо іконку в треї при старті

            hListBox = CreateWindowEx(0, L"LISTBOX", NULL,
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY | LBS_WANTKEYBOARDINPUT | LBS_HASSTRINGS | LBS_OWNERDRAWFIXED | LBS_NOINTEGRALHEIGHT,
                0, UI_HEADER_HEIGHT, UI_WIN_WIDTH, UI_WIN_HEIGHT - UI_HEADER_HEIGHT - UI_BOTTOM_HEIGHT, hwnd, (HMENU)1, NULL, NULL);
            
            SendMessage(hListBox, WM_SETFONT, (WPARAM)hFont, TRUE);
            SetWindowTheme(hListBox, L"DarkMode_Explorer", NULL);

            OldListBoxProc = (WNDPROC)SetWindowLongPtr(hListBox, GWLP_WNDPROC, (LONG_PTR)ListBoxSubclassProc);
            AddClipboardFormatListener(hwnd); // Програма стає слухачем системного буфера обміну
            break;

        case WM_TRAYICON: // Обробка кліків по іконці в треї
            if (lParam == WM_RBUTTONUP) {
                POINT pt; GetCursorPos(&pt);
                HMENU hMenu = CreatePopupMenu();
                InsertMenuW(hMenu, -1, MF_BYPOSITION | MF_STRING, 1, L"Вихід");
                
                SetForegroundWindow(hwnd); // Фокус, щоб меню коректно закривалось при кліку повз
                int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, hwnd, NULL);
                DestroyMenu(hMenu);
                
                if (cmd == 1) SendMessage(hwnd, WM_CLOSE, 0, 0);
            } else if (lParam == WM_LBUTTONDBLCLK) {
                ShowClipboardUI(false);
            }
            break;

        case WM_NCHITTEST: { // Дозволяємо тягати вікно за шапку і за нижню смужку
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

        case WM_LBUTTONDOWN: { // Клік по кнопці закриття "✕"
            POINT pt;
            pt.x = GET_X_LPARAM(lParam);
            pt.y = GET_Y_LPARAM(lParam);
            if (pt.y < UI_HEADER_HEIGHT && pt.x >= UI_WIN_WIDTH - UI_HEADER_HEIGHT) {
                // Перевірка Shift для повного закриття, інакше тільки ховаємо віконце
                if (GetKeyState(VK_SHIFT) & 0x8000) {
                    SendMessage(hwnd, WM_CLOSE, 0, 0);
                } else {
                    ShowWindow(hwnd, SW_HIDE);
                }
            }
            break;
        }

        case WM_PAINT: { // Малюємо кастомну шапку і футер
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

        case WM_CLIPBOARDUPDATE: { // Ловимо ОНОВЛЕННЯ системного буфера (Ctrl+C)
            if (ignoreClipboardUpdate) break; // Блокуємо наші ж внутрішні копіювання

            if (OpenClipboard(hwnd)) {
                HANDLE hData = GetClipboardData(CF_UNICODETEXT);
                if (hData) {
                    wchar_t* pText = static_cast<wchar_t*>(GlobalLock(hData));
                    if (pText) {
                        AddToHistory(pText); 
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

        case WM_MEASUREITEM: { // Визначаємо висоту одного запису списку
            MEASUREITEMSTRUCT* mis = (MEASUREITEMSTRUCT*)lParam;
            mis->itemHeight = g_ItemHeight; 
            return TRUE;
        }

        case WM_DRAWITEM: { // Кастомне малювання одного запису (округлені картки)
            DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lParam;
            if (dis->itemID == -1) break;

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
            
            RoundRect(hdc, cardRect.left, cardRect.top, cardRect.right, cardRect.bottom, UI_CORNER_RADIUS, UI_CORNER_RADIUS);
            SelectObject(hdc, oldBrush); SelectObject(hdc, oldPen);
            DeleteObject(bgBrush); DeleteObject(borderPen);

            wchar_t text[UI_PREVIEW_LENGTH + 10];
            SendMessage(dis->hwndItem, LB_GETTEXT, dis->itemID, (LPARAM)text);
            
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(240, 240, 240));
            
            RECT textRect = cardRect;
            textRect.left += 15; textRect.right -= 15;
            textRect.top += 10; textRect.bottom -= 10;
            DrawTextW(hdc, text, -1, &textRect, DT_WORDBREAK | DT_END_ELLIPSIS | DT_NOPREFIX);
            return TRUE;
        }

        case WM_TIMER: // Таймер для неблокуючого виконання "Ctrl+A" копіювання
            if (wParam == 2026) {
                KillTimer(hwnd, 2026);
                // Копіюємо (0x43 = 'C'), але НЕ записуємо як Alt+C буфер (false), 
                // щоб не перезатерти користувачу його цільовий запис для Alt+V
                CustomCopyOrCut(0x43, false); 
            }
            break;

        case MSG_PROCESS_HOTKEY: { // Обробка наших гарячих клавіш від хуку
            HotkeyCmd cmd = static_cast<HotkeyCmd>(wParam);
            
            if (cmd == HotkeyCmd::Layout) { TransformClipboardText(TransformMode::Layout); }  
            else if (cmd == HotkeyCmd::Copy) { CustomCopyOrCut(0x43, true); }    
            else if (cmd == HotkeyCmd::Paste) {        
                if (IsWindowVisible(hMainWindow)) {
                    int sel = SendMessage(hListBox, LB_GETCURSEL, 0, 0);
                    if (sel >= 0) PasteFromHistory(sel);
                    else {
                        // Якщо нічого не виділено у списку, логіка за замовчуванням
                        if (lastAltCCopy) PasteLastAltC();
                        else if (historyCount > 0) PasteFromHistory(0);
                    }
                } else { 
                    // Вікно закрито. Якщо є запис по Alt+C — вставляє його, інакше — найновіший
                    if (lastAltCCopy) PasteLastAltC();
                    else if (historyCount > 0) PasteFromHistory(0);
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
            else if (cmd == HotkeyCmd::Cut) { CustomCopyOrCut(0x58, true); }      
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
                // Замість блокуючого Sleep(150), який заморожував програму, 
                // запускаємо таймер. Програма-донор встигає відпрацювати Ctrl+A.
                SetTimer(hwnd, 2026, 200, NULL);
            }
            else if (cmd == HotkeyCmd::StrikeSlanted) { TransformClipboardText(TransformMode::StrikeSlanted); } 
            else if (cmd == HotkeyCmd::StrikeStraight) { TransformClipboardText(TransformMode::StrikeStraight); } 
            break;
        }

        case WM_CTLCOLORLISTBOX: { // Фарбуємо фон Listbox
            HDC hdc = (HDC)wParam;
            SetBkColor(hdc, RGB(25, 25, 25));       
            SetTextColor(hdc, RGB(240, 240, 240));  
            return (LRESULT)hDarkBrush;             
        }

        case WM_SIZE: 
            MoveWindow(hListBox, 0, UI_HEADER_HEIGHT, LOWORD(lParam), HIWORD(lParam) - UI_HEADER_HEIGHT - UI_BOTTOM_HEIGHT, TRUE);
            break;

        case WM_COMMAND: // Клік по елементу списку
            if (LOWORD(wParam) == 1 && HIWORD(wParam) == 1000) {
                PasteFromHistory(SendMessage(hListBox, LB_GETCURSEL, 0, 0));
            }
            break;

        case WM_VKEYTOITEM: // Обробка клавіатури, коли фокус у ListBox
            if (LOWORD(wParam) == VK_RETURN) { 
                PasteFromHistory(SendMessage(hListBox, LB_GETCURSEL, 0, 0)); return -2; 
            }
            if (LOWORD(wParam) == VK_ESCAPE) { 
                ShowWindow(hwnd, SW_HIDE); return -2; 
            }
            if (LOWORD(wParam) == VK_DELETE) { 
                int sel = SendMessage(hListBox, LB_GETCURSEL, 0, 0);
                if (sel >= 0 && sel < historyCount) {
                    RemoveFromHistory(sel); UpdateListBox();
                    SendMessage(hListBox, LB_SETCURSEL, sel > 0 ? sel - 1 : 0, 0); 
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

        case WM_ACTIVATE: // Коли юзер клікає поза вікном — ховаємо його
            if (LOWORD(wParam) == WA_INACTIVE) ShowWindow(hwnd, SW_HIDE); 
            break;

        case WM_CLOSE: // Явне руйнування вікна
            DestroyWindow(hwnd);
            return 0;

        case WM_DESTROY: 
            ManageTrayIcon(hwnd, NIM_DELETE); // Видаляємо іконку з трею при закритті
            RemoveClipboardFormatListener(hwnd); 
            HeapDestroy(hMemHeap); 
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, msg, wParam, lParam); 
    }
    return 0;
}

// ==========================================
// --- ТОЧКА ВХОДУ ---
// ==========================================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Логіка Мутексу (заборона множинних копій і реалізація Alt+Q як перемикача)
    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"Local\\LayoutClipboardMutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        // Якщо утиліта вже працює — знаходимо її вікно і відправляємо команду на закриття
        HWND hExistingWnd = FindWindowW(L"CustomClipboardMenu", NULL);
        if (hExistingWnd) {
            PostMessage(hExistingWnd, WM_CLOSE, 0, 0);
        }
        CloseHandle(hMutex);
        return 0; // Завершуємо цей екземпляр
    }

    InitMaps(); 

    hMemHeap = HeapCreate(0, HEAP_SIZE_LIMIT, HEAP_SIZE_LIMIT);
    if (!hMemHeap) {
        MessageBoxW(NULL, L"Помилка: Не вдалося виділити пам'ять", L"Критична помилка", MB_ICONERROR);
        return 1;
    } 
    
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
    
    // Намагаємось завантажити іконку з exe для вікна, або беремо стандартну
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
    
    // Звільнення мутексу при виході
    CloseHandle(hMutex);
    
    return 0;
}
