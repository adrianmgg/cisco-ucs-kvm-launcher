use std::time::{Duration, Instant};

use arrayvec::ArrayString;
use eyre::{Context as _, eyre};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use tap::Pipe as _;
use veil::Redact;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
pub enum PrivilegeLevel {
    Admin,
    User,
    ReadOnly,
}

#[derive(Redact, Serialize, PartialEq, Eq)]
#[serde(rename = "aaaLogin")]
pub struct LoginRequest {
    #[serde(rename = "@inName")]
    pub in_name: String,

    #[redact]
    #[serde(rename = "@inPassword")]
    pub in_password: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename = "aaaLogin")]
pub struct LoginResponse {
    #[serde(rename = "@response", deserialize_with = "serde_this_or_that::as_bool")]
    pub response: bool,
    #[serde(rename = "@outCookie")]
    pub cookie: Cookie,
    #[serde(rename = "@outRefreshPeriod")]
    pub refresh_period: u64,
    #[serde(rename = "@outPriv")]
    pub privilege: PrivilegeLevel,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "aaaLogout")]
pub struct LogoutRequest {
    // why is the cookie there twice? no idea.
    #[serde(rename = "@cookie")]
    pub cookie: Cookie,
    #[serde(rename = "@inCookie")]
    pub in_cookie: Cookie,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename = "aaaLogout")]
pub struct LogoutResponse {
    #[serde(rename = "@response", deserialize_with = "serde_this_or_that::as_bool")]
    pub response: bool,
    #[serde(rename = "@cookie")]
    pub cookie: Cookie,
    // TODO
    #[serde(rename = "@outStatus")]
    pub out_status: String,
}

#[derive(Debug, Serialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename = "aaaGetComputeAuthTokens")]
pub struct GetComputeAuthTokensRequest {
    #[serde(rename = "@cookie")]
    cookie: Cookie,
}

fn deserialize_outtokens<'de, D>(deserializer: D) -> Result<(String, String), D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    match s.split(',').collect::<Vec<_>>()[..] {
        [a, b] => Ok((a.to_owned(), b.to_owned())),
        _ => Err(serde::de::Error::custom("hello world")),
    }
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "aaaGetComputeAuthTokens")]
pub struct GetComputeAuthTokensResponse {
    #[serde(rename = "@response", deserialize_with = "serde_this_or_that::as_bool")]
    response: bool,
    #[serde(rename = "@cookie")]
    cookie: Cookie,
    #[serde(rename = "@outTokens", deserialize_with = "deserialize_outtokens")]
    out_tokens: (String, String),
}

#[derive(Debug, Serialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename = "aaaKeepAlive")]
pub struct KeepAliveRequest {
    #[serde(rename = "@cookie")]
    pub cookie: Cookie,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename = "aaaKeepAlive")]
// TODO should be an enum and handle the errorCode/errorDescr/etc. stuff
// (or maybe do that in one general type? idk)
pub struct KeepAliveResponse {
    #[serde(rename = "@response", deserialize_with = "serde_this_or_that::as_bool")]
    pub response: bool,
    #[serde(rename = "@cookie")]
    pub cookie: Cookie,
}

pub struct Client {
    credentials: Credentials,
    reqwest_client: reqwest::Client,
    base_url: Url,
    ip: String,
    auth_state: AuthState,
}

#[derive(Debug, Clone, Copy)]
enum AuthState {
    LoggedOut,
    LoggedIn(AuthStateLoggedIn),
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cookie(ArrayString<47>);

impl TryFrom<&str> for Cookie {
    type Error = eyre::Report;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() == 47 {
            Ok(Self(ArrayString::from(value).map_err(|e| eyre!("{e}"))?))
        } else {
            Err(eyre!(
                "string of length {} can't be a Cookie (must be 47 characters long)",
                value.len()
            ))
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct AuthStateLoggedIn {
    refresh_interval: Duration,
    next_refresh_deadline: Instant,
    cookie: Cookie,
    privelage: PrivilegeLevel,
}

#[derive(Redact, PartialEq, Eq)]
pub struct Credentials {
    pub username: String,
    #[redact]
    pub password: String,
}

impl Client {
    pub fn new(
        credentials: Credentials,
        ignore_cert_validation: bool,
        base_url: Url,
        ip: String,
    ) -> eyre::Result<Self> {
        let reqwest_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(ignore_cert_validation)
            .max_tls_version(reqwest::tls::Version::TLS_1_2)
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .build()?;
        Ok(Self {
            credentials,
            reqwest_client,
            base_url,
            ip,
            auth_state: AuthState::LoggedOut,
        })
    }

    async fn send_login(&mut self) -> eyre::Result<AuthStateLoggedIn> {
        async {
            let request_time = Instant::now();
            log::info!("logging in");
            let resp = self
                .reqwest_client
                .post(self.base_url.join("nuova")?)
                .body(
                    LoginRequest {
                        in_name: self.credentials.username.clone(),
                        in_password: self.credentials.password.clone(),
                    }
                    .pipe_ref(quick_xml::se::to_string)?,
                )
                .send()
                .await?;
            resp.error_for_status_ref()?;
            let resp_text = resp.text().await?;
            let resp_data: LoginResponse = resp_text
                .pipe_deref(quick_xml::de::from_str)
                .wrap_err_with(|| format!("response recieved was: {}", resp_text))?;
            let refresh_interval = Duration::from_secs(resp_data.refresh_period);
            let state = AuthStateLoggedIn {
                refresh_interval,
                next_refresh_deadline: request_time + refresh_interval,
                cookie: resp_data.cookie,
                privelage: resp_data.privilege,
            };
            self.auth_state = AuthState::LoggedIn(state);
            eyre::Result::<_>::Ok(state)
        }
        .await
        .wrap_err("error encountered while trying to log in")
    }

    async fn send_keepalive(&mut self, auth: AuthStateLoggedIn) -> eyre::Result<()> {
        async {
            let now = Instant::now();
            let resp = self
                .reqwest_client
                .post(self.base_url.join("nuova")?)
                .body(quick_xml::se::to_string(&KeepAliveRequest {
                    cookie: auth.cookie,
                })?)
                .send()
                .await?;
            resp.error_for_status_ref()?;
            let resp_text = resp.text().await?;
            let resp_data: KeepAliveResponse = resp_text
                .pipe_deref(quick_xml::de::from_str)
                .wrap_err_with(|| format!("response recieved was: {}", resp_text))?;
            self.auth_state = AuthState::LoggedIn(AuthStateLoggedIn {
                cookie: resp_data.cookie,
                next_refresh_deadline: now + auth.refresh_interval,
                ..auth
            });
            eyre::Result::<()>::Ok(())
        }
        .await
        .wrap_err("error encountered while sending keepalive")
    }

    async fn send_logout(&mut self, auth: AuthStateLoggedIn) -> eyre::Result<()> {
        async {
            log::info!("logging out");
            let resp = self
                .reqwest_client
                .post(self.base_url.join("nuova")?)
                .body(
                    LogoutRequest {
                        cookie: auth.cookie,
                        in_cookie: auth.cookie,
                    }
                    .pipe_ref(quick_xml::se::to_string)?,
                )
                .send()
                .await?;
            resp.error_for_status_ref()?;
            let resp_text = resp.text().await?;
            let resp_data: LogoutResponse = resp_text
                .pipe_deref(quick_xml::de::from_str)
                .wrap_err_with(|| format!("response recieved was: {}", resp_text))?;
            self.auth_state = AuthState::LoggedOut;
            eyre::Result::<_>::Ok(())
        }
        .await
        .wrap_err("error encountered while sending logout")
    }

    async fn ensure_logged_in(&mut self) -> eyre::Result<AuthStateLoggedIn> {
        match self.auth_state {
            AuthState::LoggedIn(s) => Ok(s),
            _ => self.send_login().await,
        }
    }

    async fn _keep_alive_poll(
        &mut self,
        deadline_fuzziness: Duration,
    ) -> eyre::Result<AuthStateLoggedIn> {
        let auth = self.ensure_logged_in().await?;
        if (Instant::now() + deadline_fuzziness) <= auth.next_refresh_deadline {
            self.send_keepalive(auth).await?;
        }
        Ok(auth)
    }

    // we don't actually use this, but i implemented it before i realized it wasn't needed so eh why remove it now
    /// call this occasionally to keep the session active
    pub async fn keep_alive_poll(&mut self, deadline_fuzziness: Duration) -> eyre::Result<()> {
        self._keep_alive_poll(deadline_fuzziness).await.map(|_| ())
    }

    async fn send_getcomputeauthtokens(&mut self) -> eyre::Result<(String, String)> {
        async {
            let auth = self._keep_alive_poll(Duration::ZERO).await?;
            log::info!("requesting auth tokens");
            let resp = self
                .reqwest_client
                .post(self.base_url.join("nuova")?)
                .body(
                    GetComputeAuthTokensRequest {
                        cookie: auth.cookie,
                    }
                    .pipe_ref(quick_xml::se::to_string)?,
                )
                .send()
                .await?;
            resp.error_for_status_ref()?;
            let resp_text = resp.text().await?;
            let resp_data: GetComputeAuthTokensResponse = resp_text
                .pipe_deref(quick_xml::de::from_str)
                .wrap_err_with(|| format!("response recieved was: {}", resp_text))?;
            // TODO should prob update our cookie from the cookie this request returns too
            eyre::Result::<_>::Ok(resp_data.out_tokens)
        }
        .await
        .wrap_err("error encountered while getting compute auth tokens")
    }

    pub async fn get_kvm_webstart_url(&mut self) -> eyre::Result<Url> {
        let tokens = self.send_getcomputeauthtokens().await?;
        let mut url = self.base_url.join("kvm.jnlp")?.clone();
        url.query_pairs_mut()
            .append_pair("cimcAddr", &self.ip)
            .append_pair("cimcName", "KVM")
            .append_pair("tkn1", &tokens.0)
            .append_pair("tkn2", &tokens.1);
        Ok(url)
    }

    pub async fn get_kvm_webstart_content(&mut self) -> eyre::Result<String> {
        let url = self.get_kvm_webstart_url().await?;
        log::info!("downloading kvm jnlp file from {url}");
        let text = self.reqwest_client.get(url).send().await?.text().await?;
        Ok(text)
    }

    pub async fn logout(&mut self) -> eyre::Result<()> {
        match self.auth_state {
            AuthState::LoggedOut => {}
            AuthState::LoggedIn(auth) => {
                self.send_logout(auth).await?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    macro_rules! ser_test {
        ($fname:ident, $expected:expr, $o:expr) => {
            #[test]
            fn $fname() {
                use crate::cisco_imc::*;
                assert_eq!(($o).pipe_ref(quick_xml::se::to_string).unwrap(), $expected);
            }
        };
    }

    macro_rules! de_test {
        ($fname:ident, $typ:path, $expected:expr, $o:expr) => {
            #[test]
            fn $fname() {
                use crate::cisco_imc::*;
                assert_eq!(
                    ($expected).pipe(quick_xml::de::from_str::<$typ>).unwrap(),
                    $o
                );
            }
        };
    }

    macro_rules! reqresp_serde_tests {
        ($modname:ident, ($s_expected:expr, $s_o:expr $(,)?), ($d_typ:path, $d_expected:expr, $d_o:expr $(,)?) $(,)?) => {
            mod $modname {
                ser_test!(ser_request, $s_expected, $s_o);
                de_test!(de_response, $d_typ, $d_expected, $d_o);
            }
        };
    }

    reqresp_serde_tests!(
        login,
        (
            r#"<aaaLogin inName="admin" inPassword="password"/>"#,
            LoginRequest {
                in_name: "admin".into(),
                in_password: "password".into(),
            }
        ),
        (
            LoginResponse,
            r#"<aaaLogin response="yes" outCookie="1217377205/85f7ff49-e4ec-42fc-9437-da77a1a2c4bf" outRefreshPeriod="600" outPriv="admin"> </aaaLogin>"#,
            LoginResponse {
                response: true,
                cookie: "1217377205/85f7ff49-e4ec-42fc-9437-da77a1a2c4bf"
                    .try_into()
                    .unwrap(),
                refresh_period: 600,
                privilege: PrivilegeLevel::Admin,
            }
        ),
    );

    reqresp_serde_tests!(
        getcomputeauthtokens,
        (
            r#"<aaaGetComputeAuthTokens cookie="1217377205/85f7ff49-e4ec-42fc-9437-da77a1a2c4bf"/>"#,
            GetComputeAuthTokensRequest {
                cookie: "1217377205/85f7ff49-e4ec-42fc-9437-da77a1a2c4bf"
                    .try_into()
                    .unwrap()
            }
        ),
        (
            GetComputeAuthTokensResponse,
            r#"<aaaGetComputeAuthTokens cookie="1217377205/85f7ff49-e4ec-42fc-9437-da77a1a2c4bf" outTokens="1804289383,846930886" response="yes"> </aaaGetComputeAuthTokens>"#,
            GetComputeAuthTokensResponse {
                response: true,
                cookie: "1217377205/85f7ff49-e4ec-42fc-9437-da77a1a2c4bf"
                    .try_into()
                    .unwrap(),
                out_tokens: ("1804289383".into(), "846930886".into()),
            }
        )
    );

    reqresp_serde_tests!(
        keepalive,
        (
            r#"<aaaKeepAlive cookie="1217377205/85f7ff49-e4ec-42fc-9437-da77a1a2c4bf"/>"#,
            KeepAliveRequest {
                cookie: "1217377205/85f7ff49-e4ec-42fc-9437-da77a1a2c4bf"
                    .try_into()
                    .unwrap()
            }
        ),
        (
            KeepAliveResponse,
            r#"<aaaKeepAlive cookie="1217377205/85f7ff49-e4ec-42fc-9437-da77a1a2c4bf" response="yes"/>"#,
            KeepAliveResponse {
                response: true,
                cookie: "1217377205/85f7ff49-e4ec-42fc-9437-da77a1a2c4bf"
                    .try_into()
                    .unwrap()
            }
        )
    );
}
