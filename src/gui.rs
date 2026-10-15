use anyhow::Result;

#[cfg(feature = "gui")]
pub fn launch_native_desktop_gui(default_source: Option<String>) -> Result<()> {
    use tao::{
        event::{Event, WindowEvent},
        event_loop::{ControlFlow, EventLoop},
        window::WindowBuilder,
    };
    use wry::WebViewBuilder;

    let bind_addr = "127.0.0.1:18765";
    let url = format!("http://{}", bind_addr);

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _ = rt.block_on(crate::server::run_http_server(bind_addr, default_source));
    });

    std::thread::sleep(std::time::Duration::from_millis(200));

    let event_loop = EventLoop::new();
    let window = WindowBuilder::new()
        .with_title("lpr Studio")
        .with_inner_size(tao::dpi::LogicalSize::new(1360.0, 860.0))
        .build(&event_loop)?;

    let _webview = WebViewBuilder::new(&window).with_url(&url).build()?;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        if let Event::WindowEvent { event: WindowEvent::CloseRequested, .. } = event {
            *control_flow = ControlFlow::Exit;
        }
    });
}

#[cfg(not(feature = "gui"))]
pub fn launch_native_desktop_gui(_default_source: Option<String>) -> Result<()> {
    anyhow::bail!("Native desktop GUI was not compiled into this standalone server build.\nTo access the Web UI, run:\n  lpr serve --bind 127.0.0.1:8080\nand open http://127.0.0.1:8080 in your browser.")
}
