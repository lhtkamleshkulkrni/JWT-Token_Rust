use actix_web::{get, App, HttpResponse, HttpServer, Responder,dev::ServiceRequest, Error};
mod auth;
mod errors;

use actix_web_httpauth::extractors::bearer::{BearerAuth, Config};
use actix_web_httpauth::extractors::AuthenticationError;
use actix_web_httpauth::middleware::HttpAuthentication;

async fn validator(req: ServiceRequest, credentials: BearerAuth) -> Result<ServiceRequest, Error> {
    let config = req
        .app_data::<Config>()
        .map(|data| data.get_ref().clone())
        .unwrap_or_else(Default::default);
    match auth::validate_token(credentials.token()) {
        Ok(res) => {
            if res == true {
                Ok(req)
            } else {
                Err(AuthenticationError::from(config).into())
            }
        }
        Err(_) => Err(AuthenticationError::from(config).into()),
    }
}

#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().json("Hello server run on 8080 port .....!!!!!")
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let authen = HttpAuthentication::bearer(validator);
        App::new()
        .wrap(authen)
        .service(hello)
    })
        .bind(("localhost", 8080))?
        .run()
        .await
}