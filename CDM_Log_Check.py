import time
import os
import datetime as dt

##### risk 개수
total_num_risk = 82
##### Technical impact scroe
High_score = 3
Medium_score = 2
Low_score = 1
##### Vulnerability factors score
Good = 1
Weak = 5
#####

def get_dirlist(rootdir):
    dirlist = []
    # python 3.6
    ''''
    with os.scandir(rootdir) as rit:
        for entry in rit:
            if not entry.name.startswith('.') and entry.is_dir():
                dirlist.append(entry.path)
    '''
    # python 3.5
    for dirpath, dirnames, filenames in os.walk('./'):
        dirlist = filenames

    dirlist.sort()  # Optional, in case you want sorted directory names

    return dirlist

## Author와 Job Name이 동일한지 여부 확인 후 동일하지 않은 경우 Alert
def Rule_01(list_data):
    state = ''
    Author = list_data[3].split('.')[1]
    Job_name = list_data[1].split(' ')

    if Job_name[0] == 'Generating':
        Job_name_3 = Job_name[4].lower().split('_')[0]
        if Job_name_3 not in Author:
            state = list_data[1].replace('.','').split(' ')[2]

    return state

def Rule_02(list_data):
    state = ''

    if list_data[2] == 'FAILED':
        state = list_data[1].replace('.','').split(' ')[2]

    return state

def Rule_03(list_all_data):
    gen_cohort_list, cleanup_cohort_list = list(), list()
    for num in range(0,len(list_all_data)):
        # print(list_all_data[num])
        Job_name = list_all_data[num].split(',')[1].replace('.','')
        Job_name1 = Job_name.split(' ')[0]
        Job_name2 = Job_name.split(' ')[2]

        if Job_name1 == 'Generating':
            if Job_name2 not in gen_cohort_list:
                gen_cohort_list.append(Job_name2)
        elif Job_name1 == 'Cleanup':
            if Job_name2 in gen_cohort_list:
                gen_cohort_list.remove(Job_name2)
        #print(Job_name, gen_cohort_list)

    return gen_cohort_list

def Rule_04(list_all_data):
    rule_4_cohort_list, rule_4_cohort_list_alert, cleanup_cohort_list = list(), list(), list()
    temp = list()
    start_time, end_time = 0, 0
    dict_cohort = dict()

    for num in range(0,len(list_all_data)):
        Job_name = list_all_data[num].split(',')[1].replace('.','')
        Job_name1 = Job_name.split(' ')[0]
        Job_name2 = Job_name.split(' ')[2]

        if Job_name1 == 'Generating':
            if Job_name2 not in dict_cohort.keys():
                dict_cohort[Job_name2] = [list_all_data[num].split(',')[4]]

        elif Job_name1 == 'Cleanup':
            if Job_name2 in dict_cohort.keys():
                if len(dict_cohort[Job_name2]) == 1 :
                    dict_cohort[Job_name2].append(list_all_data[num].split(',')[5])

    ## cohort generating과 cleanup이 제대로 되었는지 확인
    ## cohort generating과 cleanup이 제대로 되었다면, dict_cohort[ 코호트번호 ]에 2개의 시간대가 들어가야함
    ## 결국 len(dict_cohort[item])이 2가 되어야, generating과 cleanup이 이루어진것을 확인할 수 있음
    for item in dict_cohort.keys():
        if len(dict_cohort[item]) == 2:
            temp.append([item, dict_cohort[item][0], dict_cohort[item][1]])

    ## cohort
    for num in range(0,len(temp)):
        start_time = dt.datetime.strptime(temp[num][1], '%m/%d/%Y %H:%M %p').timestamp()
        end_time = dt.datetime.strptime(temp[num][2], '%m/%d/%Y %H:%M %p').timestamp()

        ## 86400 seconds => 시간을 1일 단위로 계산
        ## 28일보다 적으면 ok, 28일보다 크거나 같으면 alert
        if (end_time - start_time)/86400 < 13:
            rule_4_cohort_list.append([temp[num][0], 'R04_ok'])
        elif (end_time - start_time)/86400 >= 13:
            rule_4_cohort_list_alert.append(temp[num][0])

    return rule_4_cohort_list_alert

def Atlas_Rules(list_csvfiles):

    for fileitem in list_csvfiles:
        f = open(fileitem, encoding='utf-8-sig')
        csv_data_re = list()
        Rule1_list = list()
        Rule2_list = list()

        features = f.readline().replace('\n','')
        while True:
            line = f.readline().replace('\n','')
            if not line: break
            csv_data_re.append(line)

        ## 역순으로 데이터 출력
        csv_data = list()
        for item in csv_data_re[::-1]:
            csv_data.append(item)

        ## Features
        ## ExecutionId,Job Name,Status,Author,Start Date,End Date
        for num in range(0,len(csv_data)):
            line = csv_data[num]
            line = line.split(',')

            ## Rule1
            Rule1_state = Rule_01(line)
            Rule2_state = Rule_02(line)

            if len(Rule1_state) > 0:
                Rule1_list.append(Rule1_state)
            if len(Rule2_state) > 0:
                Rule2_list.append(Rule2_state)

        ## Rule3_state, Rule4_state는 각 코호트별 ok 와 alert를 함께 나타냄
        Rule3_state = Rule_03(csv_data)  ### 3 Rule
        Rule4_state = Rule_04(csv_data)  ### 4 Rule

        Rule1_list = list(set(Rule1_list))  ## 중복제거
        Rule2_list = list(set(Rule2_list))  ## 중복제거

        f_ATLAS = open("Login_ATLAS.txt", 'w')
        rule_list = [Rule1_list, Rule2_list, Rule3_state, Rule4_state]
        for num in range(0,len(rule_list)):
            f_ATLAS.write('Rule' + str(num + 1) + "," + ",".join(rule_list[num]) + "\n")


def Rule_05(line):
    str_state = ''
    dict_registerd = dict()

    dict_registerd['guro_user'] = '10.2.36.225'
    dict_registerd['WIN-AV5DT9A9AUO\\Administrator'] = '10.2.36.225'

    ## login_name 등록 여부 확인
    if line[1] in dict_registerd.keys():
        ## client_ip 등록 및 매칭 확인
        if line[4] not in dict_registerd[line[1]]:
            str_state = line[0]     ## spid 저장
    else:
        str_state = line[0]  ## spid 저장

    return str_state

def Rule_06(line):
    str_state = ''
    time_threshold = 5.0

    start_time = float(line[2].split(':')[0]) * 60 + float(line[2].split(':')[1])
    end_time = float(line[3].split(':')[0]) * 60 + float(line[3].split(':')[1])

    timedelta = end_time - start_time

    if timedelta >= time_threshold:
        str_state = line[0]     ## spid

    return str_state

def Rule_07(line):
    str_state = ''
    dict_registerd = list()

    login_program = line[5]

    dict_registerd = ['Microsoft JDBC Driver for SQL Server', 'Microsoft SQL Server Management Studio']

    ## login_name 등록 여부 확인
    if login_program not in dict_registerd:
        str_state = line[0]     ## spid

    return str_state

def Rule_08(line):
    str_state = ''
    dict_registerd = list()

    current_cmd = line[6]

    dict_registerd = ['AWAITING COMMAND', 'SELECT']

    ## login_name 등록 여부 확인
    if current_cmd not in dict_registerd:
        str_state = line[0]     ## spid

    return str_state

def MYSQL_Rules(list_csvfiles):
    now = time.localtime()
    for fileitem in list_csvfiles:
        csv_data = list()

        f = open(fileitem, encoding='utf-8-sig')
        features = f.readline().replace('\n','')

        while True:
            line = f.readline().replace('\n','')
            if not line: break
            csv_data.append(line)

        ## Features (x)
        ## '51', 'guro_user', '2021-03-19 15:10:32.627', '2021-03-19 15:10:32.620', '10.2.36.225', 'MicrosoftJDBCDriverforSQLServer', 'AWAITINGCOMMAND'
        ##  spid, login_name, login_start_time, login_end_time, client_ip, login_program, current_cmd
        ##  0       1               2               3               4            5           6
        f_MSSQL = open("Login_MSSQL.txt", 'w')
        rule5_list, rule6_list, rule7_list, rule8_list = list(), list(), list(), list()
        for num in range(0,len(csv_data)):
            line = csv_data[num].split(',')
            line[1] = line[1].replace('  ','').replace(' ','').replace('"','')
            line[5] = line[5].replace('  ','').replace('"','')
            line[6] = line[6].replace('  ','').replace('"','')

            if len(Rule_05(line)) > 0 :
                rule5_list.append(Rule_05(line))
            if len(Rule_06(line)) > 0:
                rule6_list.append(Rule_06(line))
            if len(Rule_07(line)) > 0:
                rule7_list.append(Rule_07(line))
            if len(Rule_08(line)) > 0:
                rule8_list.append(Rule_08(line))

        rule5_list = list(set(rule5_list))  ## 중복제거
        rule6_list = list(set(rule6_list))  ## 중복제거
        rule7_list = list(set(rule7_list))  ## 중복제거
        rule8_list = list(set(rule8_list))  ## 중복제거

        rule_list = [rule5_list, rule6_list, rule7_list, rule8_list]
        for num in range(0,len(rule_list)):
            f_MSSQL.write('Rule' + str(num + 5) + ',' + ",".join(rule_list[num]) + "\n")


if __name__ == '__main__':

    ## read : xml file body
    Atlas_Rules(['ATLAS_LOG.csv'])
    MYSQL_Rules(['MSSQL_LOG.csv'])







