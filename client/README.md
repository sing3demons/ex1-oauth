# OAuth2 Client Demo

OAuth2 Client application ที่สาธิตการใช้งาน Authorization Code Flow

## 📋 คุณสมบัติ

- 🔐 OAuth2 Authorization Code Flow
- 🛡️ CSRF Protection ด้วย state parameter
- 🎨 Web UI ที่สวยงาม
- 👤 แสดงข้อมูลผู้ใช้หลังจาก authorization
- 🔒 Session management

## 🚀 การติดตั้งและรัน

### ข้อกำหนดเบื้องต้น

- Go 1.21 หรือใหม่กว่า
- OAuth2 Server ต้องทำงานอยู่ที่ `http://localhost:8080`

### วิธีการรัน

1. **ติดตั้ง dependencies:**
```bash
go mod tidy
```

2. **รันแอปพลิเคชัน:**
```bash
go run main.go
```

3. **เปิดเบราว์เซอร์:**
```
http://localhost:3000
```

## ⚙️ การตั้งค่า

แก้ไขการตั้งค่าใน `main.go`:

```go
client := &OAuthClient{
    ClientID:     "test-client-id",     // Client ID จาก OAuth2 server
    ClientSecret: "test-client-secret", // Client Secret จาก OAuth2 server
    RedirectURL:  "http://localhost:3000/callback",
    ServerURL:    "http://localhost:8080", // OAuth2 server URL
}
```

## 🔄 OAuth2 Flow

1. **เริ่มต้น Authorization:**
   - ผู้ใช้คลิก "เข้าสู่ระบบด้วย OAuth2"
   - Client redirect ไปยัง OAuth2 server

2. **Authorization:**
   - ผู้ใช้ login ที่ OAuth2 server
   - ผู้ใช้อนุญาต client

3. **Callback:**
   - OAuth2 server redirect กลับมาพร้อม authorization code
   - Client แลกเปลี่ยน code เป็น access token

4. **Access Protected Resource:**
   - ใช้ access token เพื่อขอข้อมูลผู้ใช้
   - แสดงข้อมูลในหน้า profile

## 📁 โครงสร้างไฟล์

```
client/
├── main.go              # Main application
├── go.mod              # Go modules
├── templates/          # HTML templates
│   ├── index.html      # หน้าแรก
│   ├── profile.html    # หน้าโปรไฟล์
│   └── error.html      # หน้าแสดง error
└── README.md          # คู่มือนี้
```

## 🐳 Docker

### สร้าง Docker image:
```bash
docker build -t oauth2-client .
```

### รัน container:
```bash
docker run -p 3000:3000 oauth2-client
```

## 🛠️ API Endpoints

- `GET /` - หน้าแรก
- `GET /login` - เริ่มต้น OAuth2 flow
- `GET /callback` - OAuth2 callback endpoint
- `GET /profile` - แสดงข้อมูลผู้ใช้ (ต้อง authenticate)
- `POST /logout` - ออกจากระบบ

## 🔒 Security Features

- **State Parameter:** ป้องกัน CSRF attacks
- **Secure Cookies:** เก็บ state ใน httpOnly cookie
- **Token Validation:** ตรวจสอบ access token validity
- **HTTPS Ready:** รองรับการใช้งานผ่าน HTTPS

## 🎯 การใช้งาน

1. เปิด `http://localhost:3000`
2. คลิก "เข้าสู่ระบบด้วย OAuth2"
3. Login ที่ OAuth2 server
4. อนุญาต client เข้าถึงข้อมูล
5. ดูข้อมูลโปรไฟล์ของคุณ

## 🐛 การแก้ไขปัญหา

### Client ไม่สามารถเชื่อมต่อ OAuth2 server
- ตรวจสอบว่า OAuth2 server ทำงานอยู่ที่ `http://localhost:8080`
- ตรวจสอบ client_id และ client_secret ใน OAuth2 server

### Error "Invalid state parameter"
- ลบ cookies ของเบราว์เซอร์
- ลองเริ่มต้น OAuth2 flow ใหม่

### Token หมดอายุ
- คลิก logout แล้ว login ใหม่
- ระบบจะขอ access token ใหม่อัตโนมัติ

## 📝 หมายเหตุ

- แอปพลิเคชันนี้เป็น demo เท่านั้น ไม่ควรใช้ใน production โดยตรง
- ใน production ควรใช้ HTTPS และเก็บ client_secret อย่างปลอดภัย
- ควรใช้ database เพื่อเก็บ session และ token แทนการเก็บใน memory
