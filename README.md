# cas-go

**cas-go** is a **Centralized Authentication Service (CAS)** built with **Go**, **MySQL**, and **Redis**.  
It provides a secure, scalable, and easy-to-deploy authentication service for managing user access across multiple applications.

---

## 🚀 Features

✅ **Centralized Authentication** — single sign-on (SSO) for multiple services  
✅ **User Registration** — built-in account registration flow  
✅ **OAuth Login** — supports login via third-party providers (e.g., Google, Facebook, Discord etc.)  
✅ **Two-Factor Authentication (2FA)** — supports email OTP, time-based OTP and token verification  
✅ **Service Registry** — secure way to register and manage services  
✅ **Session Management** — cookie-based session handling  
✅ **Customizable Templates** — fully customizable HTML pages and email templates  

---


## 🧩 Getting Started

### 1. Clone and build the repository
```bash
git clone https://github.com/khanghh/cas-go.git
cd cas-go
make cas-server
```

### 2. Copy and edit the configuration
Edit config.yaml to match your environment.
```bash
cp config.example.yaml config.yaml
```
### 3. Setup environment and run
Make sure your stack have MySQL and Redis running then start the server.
```bash
./build/bin/cas-server --config ./config.yaml
```
## ⚙️ Configuration
Edit the config.yaml file to define:

```yaml
debug: false
baseURL: http://localhost:3000
listenAddr : ":3000" 
staticDir: "./static"
templateDir: "./templates"
allowOrigins: 
 - http://localhost:8080

session:
  sessionMaxAge: "24h"
  cookieName: "sid"
  cookieSecure: false
  cookieHttpOnly: true

redisURL: redis://default:123456@localhost:6379/0

mysql:
  dsn: user:password@tcp(localhost:3306)/cas?charset=utf8mb4&parseTime=True&loc=Local
  maxIdleConns: 10
  maxOpenConns: 10
  connMaxIdleTime: 10
  connMaxLifetime: 10

authProviders: 
  oauth:
    google:
      clientId: xxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.apps.googleusercontent.com
      clientSecret: xxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxx
    discord:
      clientId: xxxxxxx
      clientSecret: xxxxxx

mail:
  backend: smtp
  smtp:
    host: smtp.example.com
    port: 587
    username: admin@example.com
    password: password
    from: noreply@example.com
    tls: true
    certFile: "./cert.pem"
    keyFile: "./keypem"
    caFile: "./ca.pem"

captcha:
  provider: turnstile
  turnstile:
    siteKey: "YOUR_TURNSTILE_SITE_KEY"
    secretKey: "YOUR_TURNSTILE_SECRET_KEY"
```

## 🖥️ Screenshots
<p float="left">
  <img src="https://github.com/khanghh/cas-go/blob/screenshots/login.png?raw=true" width="49%"> 
  <img src="https://github.com/khanghh/cas-go/blob/screenshots/profile.png?raw=true" width="49%"> 
</p>

<p float="left">
  <img src="https://github.com/khanghh/cas-go/blob/screenshots/2fa_challenge.png?raw=true" width="49%"> 
  <img src="https://github.com/khanghh/cas-go/blob/screenshots/verify_otp.png?raw=true" width="49%"> 
</p>

<p float="left">
  <img src="https://github.com/khanghh/cas-go/blob/screenshots/totp_enrollment.png?raw=true" width="49%"> 
  <img src="https://github.com/khanghh/cas-go/blob/screenshots/totp_enrollment2.png?raw=true" width="49%"> 
</p>

---

## 🛠️ Contributing

Pull requests are welcome!
For major changes, please open an issue first to discuss what you’d like to change.

**Bug Reports & Feature Requests**

Please use the issue tracker to report bugs or request new features.

## 📄 License

This project is licensed under the MIT License.
See the [LICENSE](LICENSE.txt) file for details.

## ❤️ Acknowledgements

- [Go](https://golang.org/)
- [MySQL](https://www.mysql.com/)
- [Redis](https://redis.io/)
