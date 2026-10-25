// p2proxy: one program for both machines. The exit node (B) shares its
// internet connection; clients (A) reach it over a direct, encrypted QUIC
// tunnel and get a Clash subscription that routes everything through it.
#include "netutil.h" // winsock2.h before windows.h

#include <shellapi.h>
#include <wrl.h>

#include <WebView2.h>

#include "app.h"
#include "web.h"

using Microsoft::WRL::Callback;
using Microsoft::WRL::ComPtr;
using namespace p2px;

namespace {

constexpr wchar_t kClass[] = L"P2ProxyWindow";
constexpr UINT WM_TRAY = WM_APP + 1, WM_SHOWAPP = WM_APP + 2;
constexpr UINT ID_OPEN = 1001, ID_EXIT = 1002;

HWND g_hwnd = nullptr;
NOTIFYICONDATAW g_nid{};
ComPtr<ICoreWebView2Controller> g_ctrl;
ComPtr<ICoreWebView2> g_web;
bool g_hintShown = false;
std::wstring g_url;

void showWindow() {
  ShowWindow(g_hwnd, IsIconic(g_hwnd) ? SW_RESTORE : SW_SHOW);
  SetForegroundWindow(g_hwnd);
}

void openInBrowser() { ShellExecuteW(nullptr, L"open", g_url.c_str(), nullptr, nullptr, SW_SHOWNORMAL); }

void initWebView() {
  std::wstring data = appDataDir() + L"\\webview";
  HRESULT hr = CreateCoreWebView2EnvironmentWithOptions(
      nullptr, data.c_str(), nullptr,
      Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
          [](HRESULT result, ICoreWebView2Environment* env) -> HRESULT {
            if (FAILED(result) || !env) {
              logf("WebView2 is unavailable (0x%08lx); opening the browser instead", result);
              openInBrowser();
              return S_OK;
            }
            env->CreateCoreWebView2Controller(
                g_hwnd, Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
                            [](HRESULT result, ICoreWebView2Controller* ctrl) -> HRESULT {
                              if (FAILED(result) || !ctrl) {
                                openInBrowser();
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
  if (FAILED(hr)) {
    logf("WebView2 is unavailable (0x%08lx); opening the browser instead", hr);
    openInBrowser();
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
  int argc = 0;
  LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  for (int i = 1; i < argc; i++) {
    std::wstring a = argv[i];
    if (a == L"--minimized") minimized = true;
    else if (a == L"--profile" && i + 1 < argc) setProfile(argv[++i]);
    else if (a == L"--ui-port" && i + 1 < argc) app.uiPort = (uint16_t)_wtoi(argv[++i]);
    else if (a == L"--socks-port" && i + 1 < argc) app.socksPort = (uint16_t)_wtoi(argv[++i]);
  }
  LocalFree(argv);

  // One copy per user (and profile): a second launch brings the first forward.
  std::wstring title = profile().empty() ? L"p2proxy" : L"p2proxy - " + profile();
  HANDLE mutex = CreateMutexW(nullptr, TRUE, (L"Local\\p2proxy-v2-" + profile()).c_str());
  if (GetLastError() == ERROR_ALREADY_EXISTS) {
    if (HWND w = FindWindowW(kClass, title.c_str())) PostMessageW(w, WM_SHOWAPP, 0, 0);
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
  app.startRole();

  CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  WNDCLASSEXW wc{sizeof wc};
  wc.lpfnWndProc = wndProc;
  wc.hInstance = inst;
  wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
  wc.hIcon = LoadIconW(inst, MAKEINTRESOURCEW(1));
  if (!wc.hIcon) wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
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
  g_nid.hIcon = wc.hIcon;
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
  return 0;
}
