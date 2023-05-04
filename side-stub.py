
# steps: 
# 2. 写脚本
# 3. -x side-stub.py

# stdout -> uart1

# 导入gdb模块来访问gdb提供的python接口
import gdb
import threading
import serial
import time


# 用户自定义命令需要继承自gdb.Command类
class SideStub(gdb.Command):

    # gdb会提取该类的__doc__属性作为对应命令的文档
    """side-stub
    Usage: side-stub target remote /dev/tty1
           side-stub tracepoint-then-get-registers <symbol>
           side-stub tracepoint-then-get-memory <addr> <length>
           side-stub tracepoint-then-get-arguments <function name>
    """
    def __init__(self):
        # 在构造函数中注册该命令的名字
        super(self.__class__, self).__init__("side-stub", gdb.COMMAND_USER)

    def connect(self,target_remote): #暂时省略了gdb第一次连接时进行的一些确认工作
        
        self.remote=target_remote
        self.ser = serial.Serial(target_remote)
        self.write_queue_lock = threading.Lock()
        self.write_queue = []

        self.packets_queue_lock = threading.Lock()
        self.packets_queue = []

        self.msg_reader_thread = threading.Thread(target=self.msg_reader, name='msg_reader')
        self.msg_reader_thread.start()
        # self.msg_reader_thread.join()

        # self.msg_process_thread = threading.Thread(target=self.msg_process, name='msg_process')
        # self.msg_process_thread.start()
        # self.msg_process_thread.join()
        print("connected")

    # 在invoke方法中实现该自定义命令具体的功能
    # args表示该命令后面所衔接的参数，这里通过string_to_argv转换成数组
    def invoke(self, args, from_tty):
        argv = gdb.string_to_argv(args)
        if len(argv) < 1 :
            raise gdb.GdbError('输入参数数目不对，help side-stub以获得用法')
        elif argv[0]=='target' and argv[1]=='remote' and len(argv)==3:
            self.connect(argv[2])
        
        elif (argv[0]=='tracepoint-then-get-registers'):
            self.tracepoint_then_get_registers(argv[1])

        elif (argv[0]=='tracepoint_then_get_arguments'):
            self.tracepoint_then_get_arguments(argv[1])
        else:
            raise gdb.GdbError('输入参数数目不对，help side-stub以获得用法')
        
        # 使用gdb.execute来执行具体的命令
        # gdb.execute('delete ' + argv[0])
        # gdb.execute('break ' + argv[1])

    def tracepoint_then_get_registers(self,symbol):
        # self.write_queue_lock.acquire()
        command = 'vTR'
        # self.write_queue.append('#'+command+symbol+'#'+hex(sum(command.encode('ascii')) % 256)[2:])
        self.ser.write(('$'+command+symbol+'#'+hex(sum(command.encode('ascii')) % 256)[2:]).encode('ascii'))


    def tracepoint_then_get_arguments(self,fn_name):
        pass
    def disconnect(self):
        # should we close another thread here?
        self.ser.close()
        return
    def read_async_msg(self,starts_with):
        msg=''
        end_count = 10000000 # todo: set this as msg_max_len
        print("gonna loop")
        while end_count > 0:
            c = str(self.ser.read(1))#,encoding='ascii')
            gdb.execute("echo "+c)
            msg+=c
            if c == '#':
                end_count = 3
            end_count -= 1
        gdb.execute('echo '+starts_with+msg+"\n")


    
    def msg_reader(self):
        while True:
            input_stream = "" # **A** packet
            end_count = 10000000 # todo: set this as msg_max_len
            while (end_count > 0):
                c = str(self.ser.read(1),encoding='ascii')
                if c == '+':
                    pass
                elif c == '%':
                    print('Percentage Symbol')
                    self.read_async_msg(c)
                    continue
                elif c == '#':
                    end_count = 3
                    input_stream+=c
                else:
                    input_stream+=c
                end_count-=1
            self.ser.write('+'.encode('ascii'))

    def msg_process(self):
        pass

        

# 向gdb会话注册该自定义命令
SideStub()