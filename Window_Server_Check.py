
import os
import sys
import time
import datetime
from os import listdir

#####################       관리자 권한 획득       #############################
import ctypes

if ctypes.windll.shell32.IsUserAnAdmin():
    print('관리자권한으로 실행된 프로세스입니다.')
else:
    print('일반권한으로 실행된 프로세스입니다.')
#############################################################################


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

def split_w_data(xml_body):
    split_data = dict()

    for num_risk in range(1, total_num_risk + 1):
        key_val = ''
        ## delimiter unit
        str_deli_start = '[W-'
        str_deli_end = '======================================================================================================================'
        idx_start, idx_end = 0, 0

        if num_risk < 10:
            key_val = str_deli_start + '0' + str(num_risk) + ']'
        else:
            key_val = str_deli_start + str(num_risk) + ']'

        for num in range(0,len(xml_body)):
            str_buf = ''
            if key_val in xml_body[num]:
                idx_start = num

            if (idx_start > 0) and (str_deli_end in xml_body[num]):
                idx_end = num
                break

        split_data[key_val.replace('[','').replace(']','')] = xml_body[idx_start:idx_end]


    return split_data

## Technical impact score
def TI_find(W_str):
    W_str = W_str.replace(']','').replace(' ','-').split('-')
    TI_score = 0

    if int(W_str[1]) <= 45:
        TI_score = High_score
    elif (46 <= int(W_str[1]) <= 63) or (65 <= int(W_str[1]) <= 69) \
            or (71 <= int(W_str[1]) <= 74) or  (76 <= int(W_str[1])<= 82):
        TI_score = Medium_score
    else :## 64, 70, 75
        TI_score = Low_score
    return TI_score

## Vulnerability factors score
def VF_find(VF_str):
    VF_score = 0
    VF_str = VF_str.replace(' ','').split(':')[-1]

    if VF_str == '양호':
        VF_score = Good
    elif VF_str == '취약':
        VF_score = Weak
    else: ## '수동진단'
        VF_score = 0

    return VF_score

def calculate_risk_score(dict_risk):
    cal_dict, cal_list = dict(), list()

    key_list = dict_risk.keys()

    for item in key_list:
        cal_dict[item] = 0
        weakness_list, handwork_list = [], []

        for num in range(0,len(dict_risk[item])):

            #### "■ 결과 : "
            if "■ 결과 : " in dict_risk[item][num]:
                ############################## 결과값이 취약/수동진단/수동점검 인 경우 기록용으로 따로 취합
                # print("dict_risk[item][num]: ", dict_risk[item][num])
                # print("dict_risk[item][num]: ", dict_risk[item][0])

                VF_str_sub = dict_risk[item][num]
                VF_str_sub = VF_str_sub.replace(' ', '').split(':')[-1]

                if VF_str_sub == '취약':
                    weakness_list.append(dict_risk[item][0])
                    #print("weakness: ", weakness_list)
                elif VF_str_sub == '수동진단' or VF_str_sub == '수동점검':
                    handwork_list.append(dict_risk[item][0])
                    #print("handwork: ", handwork_list)
                ####################################################################################

                temp = dict_risk[item][num].replace(' ','').split(':')

                TI = TI_find(dict_risk[item][0])
                if TI == 0:
                    print("The Technical impact score isn't exist")
                VF = VF_find(dict_risk[item][num])

                cal_list.append(TI * VF)
                cal_dict[item] = TI * VF
                break

    return cal_list, cal_dict

def find_risk_level_by_category(Category_score):
    str_state = ''
    if Category_score < 0.33:
        str_state = 'insignificant'
    elif 0.33 <= Category_score < 0.55 :
        str_state = 'minor'
    elif 0.55 <= Category_score < 0.77 :
        str_state = 'moderate'
    elif 0.77 <= Category_score < 1.0 :
        str_state = 'major'
    elif Category_score == 1.0:
        str_state = 'catastrophic'

    return str_state


if __name__ == '__main__':
    filepath = 'C://cyber/Win_Server_Check_2020.bat'
    os.startfile(filepath)


    # 10초 동안 보안항목 확인 후 Risk score 단계로 이동함
    time.sleep(35)

    # C 드라이브 cyber/result 폴더 내 로그파일 읽기
    File_list = list()
    xmlfilepath = "C://cyber/result/"
    list_files = os.listdir(xmlfilepath) #get_dirlist

    print("list_files: ", list_files)

    ## xml file select
    list_xmlfiles = list()
    for item in list_files:
        if item.split('.')[-1] == 'xml':
            list_xmlfiles.append(item)

    ## read : xml file body
    #listTemp = os.listdir(xmlfilepath)
    xml_body = list()
    for item in list_xmlfiles:
        print("item: ", item)
        f = open(xmlfilepath + item)
        while True:
            line = f.readline()
            if not line:
                break
            xml_body.append(line.replace('\n',''))

    ## parsing 01 => dict에 분리하여 저장
    dict_risk_assessment = split_w_data(xml_body)
    # print("dict_risk_as {}".format(dict_risk_as))

    #############################################################################
    ## 결과값이 취약/수동진단/수동점검인 경우 기록용으로 파일 저장
    now = time.localtime()
    # f1 = open("weakness_" + "%04d.%02d.%02d" % (now.tm_year, now.tm_mon, now.tm_mday) + ".txt", 'w')
    # f2 = open("handwork_" + "%04d.%02d.%02d" % (now.tm_year, now.tm_mon, now.tm_mday) + ".txt", 'w')

    f1 = open("weakness.txt", 'w')
    f2 = open("handwork.txt", 'w')
    f3 = open("RegistryResult.txt", 'w')

    weakness, handwork = list(), list()
    keys = dict_risk_assessment.keys()
    for item in keys:
        for num in range(0, len(dict_risk_assessment[item])):
            if "■ 결과 : " in dict_risk_assessment[item][num]:
                VF_str_sub = dict_risk_assessment[item][num]
                VF_str_sub = VF_str_sub.replace(' ', '').split(':')[-1]

                if VF_str_sub == '취약':
                    #weakness.append(dict_risk_assessment[item][0])
                    #print("weakness: ", weakness)
                    f1.write(str(dict_risk_assessment[item][0]))
                    f1.write('\n')
                elif VF_str_sub == '수동진단' or VF_str_sub == '수동점검':
                    #handwork.append(dict_risk_assessment[item][0])
                    #print("handwork: ", handwork)
                    f2.write(str(dict_risk_assessment[item][0]))
                    f2.write('\n')
    f1.close()
    f2.close()
    #############################################################################


    ## 0: 패치관리, 1:로그관리, 2:계정관리, 3:서비스관리, 4:보안관리
    list_risk_score = list()
    dict_risk_score = dict()

    ## parsing 02 => key에 해당하는 dict에서의 결과 확인
    #### "■ 결과 : "
    list_risk_score_list, dict_risk_score = calculate_risk_score(dict_risk_assessment)

    Category_1, Category_2, Category_3, Category_4, Category_5 = 0, 0, 0, 0, 0

    #### 01_패치관리
    Category_1_list = ["W-32", "W-33", "W-69"]
    #### 02_로그관리
    Category_2_list = ["W-34", "W-35", "W-70", "W-71"]
    #### 03_계정관리
    Category_3_list = ["W-01","W-02","W-03","W-04","W-05","W-06",
                       "W-46","W-47","W-48","W-49","W-50","W-51",
                       "W-52","W-53","W-54","W-55","W-56","W-57"]
    #### 04_서비스관리
    Category_4_list = ["W-07", "W-08", "W-09", "W-10", "W-11", "W-12", "W-13",
                       "W-14", "W-15", "W-16", "W-17", "W-18", "W-19", "W-20",
                       "W-21", "W-22", "W-23", "W-24", "W-25", "W-26", "W-27",
                       "W-28", "W-29", "W-30", "W-31", "W-58", "W-59", "W-60",
                       "W-61", "W-62", "W-63", "W-64", "W-65", "W-66", "W-67", "W-68"]
    #### 05_보안관리
    Category_5_list = ["W-36", "W-37", "W-38", "W-39", "W-40", "W-41", "W-42",
                       "W-43", "W-44", "W-45", "W-72", "W-73", "W-74", "W-75",
                       "W-76", "W-77", "W-78", "W-79", "W-80", "W-81", "W-82"]

    for key in dict_risk_score.keys():
        if key in Category_1_list:
            Category_1 = Category_1 + dict_risk_score[key]
        elif key in Category_2_list:
            Category_2 = Category_2 + dict_risk_score[key]
        elif key in Category_3_list:
            Category_3 = Category_3 + dict_risk_score[key]
        elif key in Category_4_list:
            Category_4 = Category_4 + dict_risk_score[key]
        elif key in Category_5_list:
            Category_5 = Category_5 + dict_risk_score[key]

    ### Normalization
    Nor_Cate_1 = (Category_1 - 1) / (10 - 1)
    Nor_Cate_2 = (Category_2 - 6) / (30 - 6)
    Nor_Cate_3 = (Category_3 - 34) / (170 - 34)
    Nor_Cate_4 = (Category_4 - 91) / (455 - 91)
    Nor_Cate_5 = (Category_5 - 44) / (200 - 44)

    ## find_risk_level_by_category
    State_Cate = list()
    State_Cate_1, State_Cate_2, State_Cate_3, State_Cate_4, State_Cate_5= '', '', '', '', ''
    State_Cate_1 = find_risk_level_by_category(Nor_Cate_1)
    State_Cate_2 = find_risk_level_by_category(Nor_Cate_2)
    State_Cate_3 = find_risk_level_by_category(Nor_Cate_3)
    State_Cate_4 = find_risk_level_by_category(Nor_Cate_4)
    State_Cate_5 = find_risk_level_by_category(Nor_Cate_5)

    Name_Cate = ["account", "log", "patch", "security", "service"]
    State_Cate = [State_Cate_3, State_Cate_2, State_Cate_1, State_Cate_5, State_Cate_4]

    print("patch {} {}".format(Category_1, State_Cate_1))
    print("log {} {}".format(Category_2, State_Cate_2))
    print("account {} {}".format(Category_3, State_Cate_3))
    print("service {} {}".format(Category_4, State_Cate_4))
    print("security {} {}".format(Category_5, State_Cate_5))

    for i in range(0, 5):
        f3.write(str(Name_Cate[i]) + "," + str(State_Cate[i]))
        f3.write('\n')
    f3.close()