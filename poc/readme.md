### POC 코드

해당 poc 폴더 안의 코드는 개념증명 코드입니다.  
실제 운영 및 서비스에는 Rust 기반 빌드된 코드를 사용하세요  

### POC 코드 종류
`python
    app.py - socket POC
    export-header.py - 헤더 추출 및 RFC 규격 기반 헤더 응답
    hex.py - 16 bin 데이터 생성
    send-dns.py - 재귀적 요청 리졸버 (V 1.0 + )
    primary.py - 재귀적 리졸버 2차 구현 (V2.0 +)
`