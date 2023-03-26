use axum::{Router, routing::get};

#[tokio::main]
async fn main() {
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));

    axum::Server::bind(&"0.0.0.0:8000".parse().unwrap()).serve(app.into_make_service()).await.unwrap();
}
