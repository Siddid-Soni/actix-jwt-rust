use std::io::Result;
use actix_web::{web, App, HttpServer};

mod extractors;
mod scopes;
use scopes::uesr::user_scope;

#[actix_web::main]
async fn main() -> Result<()> {
    HttpServer::new(|| {
        App::new()
            .app_data(web::Data::new(String::from("h3vlw/^ic1ZDb/f4k_9Iv8i!};3bE")))
            .service(user_scope())
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}