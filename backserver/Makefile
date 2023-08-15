# 编译器设置
CC = gcc

# 编译器选项，例如 -Wall 开启所有警告，-g 添加调试信息
CFLAGS = -Wall -g

# 头文件所在的文件夹
INCLUDES = -I../include

# 源文件列表
COMMON_SOURCES = ../log/log.c ../config/read_cfg.c 
BACKSERVER_SOURCES = backserver.c $(COMMON_SOURCES)  file_trans.c
CLIENT_SOURCES = restore.c $(COMMON_SOURCES) ../client/copyfile.c

# 目标可执行文件名
BACKSERVER_TARGET = backserver
CLIENT_TARGET = restore

all: $(BACKSERVER_TARGET) $(CLIENT_TARGET)

$(BACKSERVER_TARGET): $(BACKSERVER_SOURCES)
	$(CC) $(CFLAGS) $(INCLUDES) $(BACKSERVER_SOURCES) -o $(BACKSERVER_TARGET)

$(CLIENT_TARGET): $(CLIENT_SOURCES)
	$(CC) $(CFLAGS) $(INCLUDES) $(CLIENT_SOURCES) -o $(CLIENT_TARGET)

clean:
	rm -f $(BACKSERVER_TARGET) $(CLIENT_TARGET)
