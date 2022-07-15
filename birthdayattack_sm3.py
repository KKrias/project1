from SM3 import SM3
import time
X_arr=[]
Y_arr=[]
def Gen_X(n):
    d=int(n/2)
    collision_num=int(n/4)
    for i in range(2**d):
        plain='0' * d + bin(i)[2:]
        X_arr.append(SM3(plain)[:collision_num])
        #print(SM3(plain))
def match_Y(n):
    d=int(n/2)
    collision_num=int(n/4)
    for i in range(1,2**d):
        plain=bin(i)[2:]+'1'*d
        sm3_y=SM3(plain)[:collision_num]
        for j in X_arr:
            if sm3_y==j:
                print(X_arr.index(j))
                print(i)
a=time.time()
Gen_X(32)
match_Y(32)
b=time.time()
print("碰撞用时:",b-a,"s")
