// p2proxy: one program for both machines. The exit node (B) shares its
// internet connection; clients (A) reach it over a direct, encrypted QUIC
// tunnel and get a Clash subscription that routes everything through it.
#include "netutil.h" // winsock2.h before windows.h

#include <shellapi.h>
#include <wrl.h>

#include <WebView2.h>

#include "app.h"
#include "update.h"
#include "web.h"

using Microsoft::WRL::Callback;
using Microsoft::WRL::ComPtr;
using namespace p2px;

namespace {

constexpr wchar_t kClass[] = L"P2ProxyWindow";
constexpr UINT WM_TRAY = WM_APP + 1, WM_SHOWAPP = WM_APP + 2, WM_RESTART = WM_APP + 3;
constexpr UINT ID_OPEN = 1001, ID_EXIT = 1002;
constexpr UINT_PTR TIMER_WEBVIEW = 1;

HWND g_hwnd = nullptr;
NOTIFYICONDATAW g_nid{};
ComPtr<ICoreWebView2Controller> g_ctrl;
ComPtr<ICoreWebView2> g_web;
bool g_hintShown = false, g_restart = false, g_wasVisible = true;
int g_webviewTries = 0;
std::wstring g_url, g_keepArgs; // arguments a restart passes on

// Right after an update the previous copy's WebView2 may still be closing,
// so retry a few times before falling back to the browser.
void webviewFailed(HRESULT hr) {
  if (++g_webviewTries < 6) {
    SetTimer(g_hwnd, TIMER_WEBVIEW, 1000, nullptr);
    return;
  }
  logf("WebView2 is unavailable (0x%08lx); opening the browser instead", hr);
  ShellExecuteW(nullptr, L"open", g_url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

void showWindow() {
  ShowWindow(g_hwnd, IsIconic(g_hwnd) ? SW_RESTORE : SW_SHOW);
  if (!SetForegroundWindow(g_hwnd)) {
    // Windows refused the foreground: at least put the window on top.
    SetWindowPos(g_hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    SetWindowPos(g_hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
  }
}

void initWebView() {
  std::wstring data = appDataDir() + L"\\webview";
  HRESULT hr = CreateCoreWebView2EnvironmentWithOptions(
      nullptr, data.c_str(), nullptr,
      Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
          [](HRESULT result, ICoreWebView2Environment* env) -> HRESULT {
            if (FAILED(result) || !env) {
              webviewFailed(result);
              return S_OK;
            }
            env->CreateCoreWebView2Controller(
                g_hwnd, Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
                            [](HRESULT result, ICoreWebView2Controller* ctrl) -> HRESULT {
                              if (FAILED(result) || !ctrl) {
                                webviewFailed(result);
                                return S_OK;
                              }
                              g_ctrl = ctrl;
                              g_ctrl->get_CoreWebView2(&g_web);
                              ComPtr<ICoreWebView2Settings> s;
                              g_web->get_Settings(&s);
                              s->put_IsStatusBarEnabled(FALSE);
                              s->put_AreDevToolsEnabled(FALSE);
                              // Links that open a new window go to the default browser.
                              g_web->add_NewWindowRequested(
                                  Callback<ICoreWebView2NewWindowRequestedEventHandler>(
                                      [](ICoreWebView2*, ICoreWebView2NewWindowRequestedEventArgs* args) -> HRESULT {
                                        LPWSTR uri = nullptr;
                                        args->get_Uri(&uri);
                                        if (uri) {
                                          ShellExecuteW(nullptr, L"open", uri, nullptr, nullptr, SW_SHOWNORMAL);
                                          CoTaskMemFree(uri);
                                        }
                                        args->put_Handled(TRUE);
                                        return S_OK;
                                      })
                                      .Get(),
                                  nullptr);
                              RECT r;
                              GetClientRect(g_hwnd, &r);
                              g_ctrl->put_Bounds(r);
                              g_web->Navigate(g_url.c_str());
                              return S_OK;
                            })
                            .Get());
            return S_OK;
          })
          .Get());
  if (FAILED(hr)) webviewFailed(hr);
}

// Starts the freshly installed copy with the same settings; it waits for this
// process to exit before taking over.
void startNewCopy() {
  std::wstring cmd = L"\"" + exePath() + L"\"" + g_keepArgs + (g_wasVisible ? L"" : L" --minimized") +
                     L" --wait-pid " + std::to_wstring(GetCurrentProcessId());
  STARTUPINFOW si{sizeof si};
  PROCESS_INFORMATION pi{};
  if (CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    logf("restarting into the new version");
  } else {
    logf("could not start the new version (error %lu); start p2proxy again", GetLastError());
  }
}

LRESULT CALLBACK wndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
  switch (msg) {
  case WM_SIZE:
    if (g_ctrl) {
      RECT r;
      GetClientRect(h, &r);
      g_ctrl->put_Bounds(r);
    }
    return 0;
  case WM_CLOSE:
    // Closing the window keeps the tunnel running; quit from the tray icon.
    ShowWindow(h, SW_HIDE);
    if (!g_hintShown) {
      g_hintShown = true;
      g_nid.uFlags = NIF_INFO;
      wcscpy_s(g_nid.szInfoTitle, L"p2proxy 仍在后台运行");
      wcscpy_s(g_nid.szInfo, L"右键托盘图标可以打开主界面或退出。");
      Shell_NotifyIconW(NIM_MODIFY, &g_nid);
    }
    return 0;
  case WM_TRAY:
    if (LOWORD(lp) == WM_LBUTTONUP || LOWORD(lp) == WM_LBUTTONDBLCLK) {
      showWindow();
    } else if (LOWORD(lp) == WM_RBUTTONUP || LOWORD(lp) == WM_CONTEXTMENU) {
      HMENU m = CreatePopupMenu();
      AppendMenuW(m, MF_STRING, ID_OPEN, L"打开主界面");
      AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
      AppendMenuW(m, MF_STRING, ID_EXIT, L"退出 p2proxy");
      POINT pt;
      GetCursorPos(&pt);
      SetForegroundWindow(h);
      TrackPopupMenu(m, TPM_RIGHTBUTTON, pt.x, pt.y, 0, h, nullptr);
      DestroyMenu(m);
    }
    return 0;
  case WM_COMMAND:
    if (LOWORD(wp) == ID_OPEN) showWindow();
    if (LOWORD(wp) == ID_EXIT) DestroyWindow(h);
    return 0;
  case WM_SHOWAPP:
    showWindow();
    return 0;
  case WM_RESTART:
    g_restart = true;
    g_wasVisible = IsWindowVisible(h);
    DestroyWindow(h);
    return 0;
  case WM_TIMER:
    if (wp == TIMER_WEBVIEW) {
      KillTimer(h, TIMER_WEBVIEW);
      initWebView();
    }
    return 0;
  case WM_DESTROY:
    PostQuitMessage(0);
    return 0;
  }
  return DefWindowProcW(h, msg, wp, lp);
}

} // namespace

int APIENTRY wWinMain(HINSTANCE inst, HINSTANCE, LPWSTR, int) {
  SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
  App& app = App::get();
  bool minimized = false;
  DWORD waitPid = 0;
  int argc = 0;
  LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  for (int i = 1; i < argc; i++) {
    std::wstring a = argv[i];
    bool keep = true;
    if (a == L"--minimized") {
      minimized = true;
      keep = false;
    } else if (a == L"--wait-pid" && i + 1 < argc) {
      waitPid = (DWORD)_wtoi(argv[++i]);
      keep = false;
    } else if (a == L"--profile" && i + 1 < argc) {
      setProfile(argv[i + 1]);
    } else if (a == L"--ui-port" && i + 1 < argc) {
      app.uiPort = (uint16_t)_wtoi(argv[i + 1]);
    } else if (a == L"--socks-port" && i + 1 < argc) {
      app.socksPort = (uint16_t)_wtoi(argv[i + 1]);
    }
    if (keep && i + 1 < argc && (a == L"--profile" || a == L"--ui-port" || a == L"--socks-port")) {
      g_keepArgs += L" " + a + L" \"" + argv[i + 1] + L"\"";
      i++;
    }
  }
  LocalFree(argv);
  // After an update: let the previous copy exit and release its ports first.
  if (waitPid) {
    if (HANDLE p = OpenProcess(SYNCHRONIZE, FALSE, waitPid)) {
      WaitForSingleObject(p, 20000);
      CloseHandle(p);
    }
  }
  cleanupOldFiles();

  // One copy per user (and profile): launching it again shows the running
  // copy instead (except from autostart, which passes --minimized).
  std::wstring title = profile().empty() ? L"p2proxy" : L"p2proxy - " + profile();
  HANDLE mutex = CreateMutexW(nullptr, TRUE, (L"Local\\p2proxy-v2-" + profile()).c_str());
  if (GetLastError() == ERROR_ALREADY_EXISTS) {
    CloseHandle(mutex);
    if (!minimized) {
      // The running copy may still be starting up; give it time to make its window.
      HWND w = nullptr;
      for (int i = 0; i < 100 && !(w = FindWindowW(kClass, title.c_str())); i++) Sleep(100);
      if (w) {
        // We were just started by the user, so we may hand the foreground on;
        // without this the window would only flash in the taskbar.
        DWORD pid = 0;
        GetWindowThreadProcessId(w, &pid);
        AllowSetForegroundWindow(pid);
        PostMessageW(w, WM_SHOWAPP, 0, 0);
      }
    }
    return 0;
  }

  WinsockInit winsock;
  initLog();
  logf("p2proxy %s starting", P2PX_VERSION);
  std::string err;
  if (!Quic::init(err)) {
    MessageBoxW(nullptr, toWide("QUIC 初始化失败：" + err).c_str(), L"p2proxy", MB_ICONERROR);
    return 1;
  }
  app.load();
  WebServer web;
  if (!web.start(app.uiPort, err)) {
    MessageBoxW(nullptr, toWide(err).c_str(), L"p2proxy", MB_ICONERROR);
    return 1;
  }
  g_url = L"http://127.0.0.1:" + std::to_wstring(app.uiPort) + L"/";
  app.setRestartHook([] { PostMessageW(g_hwnd, WM_RESTART, 0, 0); });
  app.startRole();
  app.startUpdateChecks();

  CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  WNDCLASSEXW wc{sizeof wc};
  wc.lpfnWndProc = wndProc;
  wc.hInstance = inst;
  wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
  wc.hIcon = LoadIconW(inst, MAKEINTRESOURCEW(1));
  if (!wc.hIcon) wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
  // The small size, drawn for 16-24 px, keeps the title bar and tray crisp.
  wc.hIconSm = (HICON)LoadImageW(inst, MAKEINTRESOURCEW(1), IMAGE_ICON, GetSystemMetrics(SM_CXSMICON),
                                 GetSystemMetrics(SM_CYSMICON), 0);
  wc.hbrBackground = CreateSolidBrush(RGB(17, 19, 24));
  wc.lpszClassName = kClass;
  RegisterClassExW(&wc);
  UINT dpi = GetDpiForSystem();
  g_hwnd = CreateWindowExW(0, kClass, title.c_str(), WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                           MulDiv(960, dpi, 96), MulDiv(780, dpi, 96), nullptr, nullptr, inst, nullptr);

  g_nid.cbSize = sizeof g_nid;
  g_nid.hWnd = g_hwnd;
  g_nid.uID = 1;
  g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
  g_nid.uCallbackMessage = WM_TRAY;
  g_nid.hIcon = wc.hIconSm ? wc.hIconSm : wc.hIcon;
  wcsncpy_s(g_nid.szTip, title.c_str(), _TRUNCATE);
  Shell_NotifyIconW(NIM_ADD, &g_nid);

  if (!minimized) ShowWindow(g_hwnd, SW_SHOW);
  initWebView();

  MSG m;
  while (GetMessageW(&m, nullptr, 0, 0) > 0) {
    TranslateMessage(&m);
    DispatchMessageW(&m);
  }

  Shell_NotifyIconW(NIM_DELETE, &g_nid);
  g_web.Reset();
  g_ctrl.Reset();
  app.shutdown();
  web.stop();
  Quic::cleanup();
  logf("p2proxy stopped");
  ReleaseMutex(mutex);
  CloseHandle(mutex);
  if (g_restart) startNewCopy();
  return 0;
}
