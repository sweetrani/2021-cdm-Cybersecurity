# 2021-cdm-Cybersecurity
보안점검 관리 도구

[1] CDM Server 접속로그에 대한 보안점검 (ATLAS & MSSQL)
- ATLAS 와 R 도구를 통해 연구진이 CDM 서버 접근 시 로그 이벤트 발생
- ATLAS & MSSQL 저장되는 로그를 기반으로 8가지 Rule 생성하여 사후적 보안점검을 진행

>> ATLAS Rule
	1	Author와 Job Name이 동일한지 여부 확인 후 동일하지 않은 경우 (Cohort num 출력)
	2	Cohort Status의 values 확인 후 FAILED 일 때 (Cohort num 출력)
	3	동일 Cohort 넘버간의 Generating과 Cleanup 이 이루어졌는지 확인한 후 아직 Cleanup이 되지 않은 (Cohort num 출력)
	4	동일 Cohort 넘버에 대해 Cohort 유지시간을 확인하여 정상 상태일 때의 유지 시간 평균값을 초과할 경우 (Cohort num 출력)
  
>> MSSQL Rule
	5	spid를 기준으로 DB 접속 주소 (client_ip) 와 login_name (ex. guro_user) 를 비교하여 매칭되지 않을 경우 (SPID 출력)
	6	spid를 기준으로 DB 접속 유지 시간을 계산하여 제한된 범위를 초과할 경우 (SPID 출력)
	7	spid를 기준으로 정의되지 않은 login_program 이 존재할 경우 (SPID 출력)
	8	spid를 기준으로 정의되지 않은 current_cmd 이 존재할 경우 (SPID 출력)

[2] CDM Server가 있는 Window Server의 보안점검 도구 개발
- 윈도우 서버 취약점 분석 및 평가를 진행하기 위해 5가지 보안점검 항목 및 하부항목으로 세분화하여 보안점검 진행
- 하부 평가 항목은 보안 안전성 등급 (Risk level)을 High, Medium, Low로 구분
- 5가지 평가 항목 내 세부 항목은 동시에 수행되며, 보안 평가가 완료되면 진단 결과가 양호 (Good)와 취약 (Weak)로 출력

>> Risk Score
![image](https://user-images.githubusercontent.com/78719287/140642532-d5cf26ba-b0cd-4f6d-a379-1156972192f9.png)
