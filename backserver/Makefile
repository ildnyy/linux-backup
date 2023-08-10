# 编译器设置
CC = gcc

# 编译器选项，例如 -Wall 开启所有警告，-g 添加调试信息
CFLAGS = -Wall -g

# 头文件所在的文件夹
INCLUDES = -I../include

# 源文件列表
SOURCES = backserver.c  ../log/log.c

# 目标可执行文件名
TARGET = backserver

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(INCLUDES) $(SOURCES) -o $(TARGET)

clean:
	rm -f $(TARGET)
