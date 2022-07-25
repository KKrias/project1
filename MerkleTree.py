from SM3 import SM3
import math
import time
import random
def gen_element(n):  #mktree的第0层为原始数据
    data=[]
    for i in range(n):
        data.append(random.randint(1,n))
    return data
def merkleTree(data):
    mktree=[[SM3(str(hex(i)[2:])) for i in data]]
    depth = math.ceil(math.log2(len(mktree[0])) + 1)  # merkle tree深度
    for i in range(depth-1):  #由原始数据到root_hash,需要计算depth层,第一层前缀和其他层不一样 所以预处理好
        num=len(mktree[i])  #当前层元素数量
        temp_hash=[SM3("1"+mktree[i][j*2]+ mktree[i][j*2+1]) for j in range(int (num/2))]
        if num %2!=0:  #落单直接升入下一层
            temp_hash.append(mktree[i][-1])
        mktree.append(temp_hash)
    return mktree

def proof_function(hash_element,pfarr):
    temp=hash_element
    #print('hash_element',temp)
    #print('pfarr',pfarr)
    lenth = len(pfarr)-1
    for i in pfarr:
        if i[0]=='l':
            temp=SM3('1'+temp+i[1])
            #print("计算数值:",temp)
        else:
            temp=SM3('1'+i[1]+temp)
            #print("计算数值:", temp)
    return temp

def proof_of_existence(mktree,element):   #该元素为十六进制表示
    hash_element=SM3(element)
    result_index=0
    if hash_element in mktree[0]:
        result_index=mktree[0].index(hash_element)  #拿到要证明存在性的元素下标
    else:
        print("不符合条件")
        return 0

    pfarr=[]    #后续证明存在性需要的树上的元素
    depth = math.ceil(math.log2(len(mktree[0])) + 1)  # merkle tree深度
    temp = result_index
    for i in range(depth-1):
        if temp % 2 == 0:
            pfarr.append(['l',mktree[i][temp + 1]])
        else:
            pfarr.append(['r',mktree[i][temp - 1]])
        temp = int(temp / 2)
    result=proof_function(hash_element, pfarr)
    if result==mktree[-1][0]:
        print("该元素",element,"存在于merkle树中")
        return True
    else:
        print("不存在")
        return False

def Nonexistence_proof(data,mktree,element):
    pre=0
    next=0
    data.sort()
    for i in data:
        if element>i:
            pre=data.index(i)
        else:
            next=data.index(i)
            break
    if proof_of_existence(mktree,hex(data[pre])[2:]) and proof_of_existence(mktree,hex(data[next])[2:]):
        print("比该元素大的元素和比该元素小的元素存在于merkle树中且相邻,所以该元素不存在")
    else:
        print('存在')



a=time.time()
data=gen_element(100000)
mktree=merkleTree(data)
#print('mktree',mktree)
proof_of_existence(mktree,'a')
b=time.time()
print("运行时间为:",b-a,'s')
while(1):
    ele=random.randint(1,100000)
    if ele not in data:
        break
Nonexistence_proof(data,mktree,ele)
c=time.time()
print("运行时间为:",c-a,'s')





