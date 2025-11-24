# PFN Notepad Editor

> Windows 커널 권한으로 PFN(Physical Frame Number)을 변경합니다.  
> BSOD와 같은 위험이 크기에 테스트 환경에서만 사용하기를 권장합니다.

---



## 1. 프로젝트 개요

- 커널 드라이버가 제공하는 IOCTL
  - `IOCTL_SET_PID` : 타겟 프로세스 PID 설정  
  - `IOCTL_SET_VA`  : VA(가상주소)를 넘기면 해당 페이지의 물리주소/PFN을 돌려줌  
  - `IOCTL_SET_PFN` : 현재 프로세스의 특정 VA가 가리키는 페이지의 PFN을 교체

- 서버(`ioctlapp.exe`)
  - Notepad 프로세스 메모리에서 특정 문자열이 들어 있는 페이지를 찾아 그 PFN을 가져오고
  - 서버 프로세스의 페이지와 Notepad 페이지의 PFN을 교체

- 클라이언트(`client.exe`)
  - TCP로 서버에 연결해서 커맨드를 보내고, 패턴 검색 및 문자열 치환을 수행
  - 그 결과를 Notepad 화면에서 바로 확인



## 2. 구성 요소

- **커널 드라이버**
  - WDK 샘플 기반(`sioctl.sys`)  
  - `IOCTL_SET_PID`, `IOCTL_SET_VA`, `IOCTL_SET_PFN` 구현

- **서버 (`ioctlapp.exe`)**
  - 드라이버 로딩/오픈 + TCP 서버 기능 추가
  - 클라이언트 명령 처리(`h`, `f`, `1`~`6`, `q`)

- **클라이언트 (`client.exe`)**
  - 간단한 TCP CLI 클라이언트
  - 실행 시 서버 IP/Port 입력 후, `pfn>` 프롬프트에서 명령 전송



## 3. 빌드

- OS: Windows 10 / 11 x64 (테스트용 VM 권장)
- Visual Studio + WDK (드라이버 빌드용)

### 3.1 드라이버 및 서버 빌드

1. server 폴더의 ioctl.sln 솔루션 열기
2. 솔루션 빌드
3. sioctl.sys 드라이버와 ioctlapp.exe 생성 확인

### 3.2 클라이언트 빌드

1. client 폴더의 client.c 빌드
2. cl client.c
3. client.exe 생성 확인



## 4. 실행 방법

### 4.1 서버 실행

> ⚠️ 커널 드라이버를 다루기 때문에 반드시 관리자 권한으로 실행해주세요.

실행 예시:

```text
ioctlapp.exe 1234
```

출력 예시:

```text
[*] PFN server listening on 0.0.0.0:1234
```

### 4.2 클라이언트 실행

> ⚠️ VM 환경이 아닌 Host 환경에서 실행해주세요.

실행 예시:

```text
client.exe
```

출력 예시:

```text
Server IP: 192.168.xxx.xxx    # 서버가 돌고 있는 Windows VM IP
Port: 1234                    # 서버에 넘긴 포트 번호
[*] connecting to 192.168.xxx.xxx:1234 ...
[+] connected.
connected from 192.168.xxx.x
pfn>
```



## 5. 명령어

### 5.1 명령어 요약

| 명령                | 설명                                                                                 |
|---------------------|--------------------------------------------------------------------------------------|
| `h`                 | 사용법(help) 출력                                                                    |
| `f <exe> <pattern>` | 프로세스 메모리에서 UTF-16 문자열 검색 → PID / VA 자동 탐색 후 `notepadPfn` 저장    |
| `1`                 | 서버 프로세스에서 4KB 페이지 할당(`pVa`), 0으로 초기화                              |
| `2`                 | 현재 프로세스 PID + `pVa`로 드라이버 IOCTL 호출 → `oldPfn` 저장                     |
| `3`                 | `notepadPfn >> 12` 값을 `IOCTL_SET_PFN`으로 전달 → PFN 스왑                         |
| `4 <pattern>`       | `pVa` 페이지(현재는 Notepad 물리 페이지)에 대해 UTF-16LE 패턴 검색 → `pHit` 기록    |
| `5 <new_text>`      | `pHit` 위치에 새 문자열(UTF-16LE) 덮어쓰기 → Notepad 화면 내용 변경                 |
| `6`                 | `oldPfn >> 12`로 `IOCTL_SET_PFN` 호출 → PFN 원복                                    |
| `q`                 | 세션 및 서버 종료                                                                    |

### 5.2 명령어 흐름

```text
# 1) 사용법 출력
pfn> h

# 2) Notepad 프로세스에서 패턴이 있는 페이지 찾고 PFN 저장
pfn> f notepad.exe "pattern"

# 3) 서버 프로세스에서 4KB 페이지 하나 할당
pfn> 1

# 4) 현재 pVa가 가리키는 원래 PFN(oldPfn) 저장
pfn> 2

# 5) pVa 페이지의 PFN을 notepad 쪽 페이지로 스왑
pfn> 3

# 6) 스왑된 페이지(pVa) 안에서 패턴 찾기
pfn> 4 "pattern"

# 7) 해당 위치 문자열을 새 문자열로 치환
pfn> 5 "new_text"

# 8) PFN 원복
pfn> 6

# 9) 세션 및 서버 종료
pfn> q
```



## 6. demo video
![Image](https://github.com/user-attachments/assets/69aa348d-4442-475a-a718-1ce51ed51afd)
