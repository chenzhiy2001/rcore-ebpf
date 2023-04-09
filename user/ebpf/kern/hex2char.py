import os

file = ""


def f():
    with open("{}.o".format(file), "rb") as f:
        arr = f.read()
    
    with open("{}.dump".format(file), "w") as f:
        idx = 0
        for i in arr:
            f.write(str(i))
            f.write(",")
            idx = idx + 1
            if (idx % 20 == 0):
                f.write('\n')
    print("total len:{}".format(len(arr)))

if __name__ == "__main__":
    print("input file name")
    file = input()
    f()