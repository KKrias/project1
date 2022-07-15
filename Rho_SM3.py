from SM3 import SM3
import time
n=8    #8B , 32bit
a='616263'
arr=[]
arr.append(SM3(a)[:n])  #
flag=0
sta=time.time()
while(1):
    temp=SM3(arr[-1])    #下一个的输入,上次结束时最后一个哈希值
    t_sm3=SM3(temp)[:n]
    for j in arr:
        if t_sm3==j:
            flag=1
            print(arr.index(j),"该碰撞哈希值为:",j,"   当前元素标号为:",len(arr),t_sm3)
            break
    if flag==1:
        break
    arr.append(t_sm3)
end=time.time()
print(end-sta,"s")
