import os
import re
from datetime import datetime


def rename_file(file_path):
    # 获取文件名和扩展名
    file_name, file_ext = os.path.splitext(file_path)

    # 检查目标文件是否存在
    if os.path.exists(file_path):
        # 如果目标文件存在，删除或者重命名它
        # os.remove(file_path)  # 删除文件
        # 或者可以选择重命名文件
        # new_file_path = file_name + '-new' + file_ext
        # os.rename(file_path, new_file_path)
        print('exists')
    else :
        # 重命名文件
        new_file_path = file_name
        os.rename(file_path, new_file_path)
        print(f'Renamed file: {file_path} -> {new_file_path}')




# 获取当前目录下的所有文件夹
folders = [folder for folder in os.listdir('.') if os.path.isdir(folder)]

# 遍历所有文件夹
for folder in folders:
    if folder.endswith('.assets'):
        rename_file(folder)

# 获取当前目录下的所有文件
files = [file for file in os.listdir('.') if os.path.isfile(file)]

# 遍历所有文件
for file in files:
    if file.endswith('.md'):
        with open(file, 'r', encoding='utf-8') as f:
            content = f.read()

        # 使用正则表达式匹配markdown形式的图片链接
        pattern = r'!\[.*\]\((.*?)\)'
        matches = re.findall(pattern, content)

        # 遍历匹配到的图片链接
        for match in matches:
            # 提取图片名称
            image_name = match.split('\\')[-1]
            # image_name = '![]('+ image_name +')'
            # 替换markdown形式的图片链接为图片名称
            content = content.replace(match, image_name)
            print(image_name)

        with open(file, 'w', encoding='utf-8') as f:
            f.write(content)
            print(f'Processed file: {file}')



def add_content_to_files():
    # 获取当前时间
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # 遍历当前目录下所有文件
    for file_name in os.listdir():
        if file_name.endswith('.md'):
            file_path = os.path.join(os.getcwd(), file_name)

            # 打开文件并读取内容的前几行
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            # 判断文件开头是否已存在指定内容
            if not lines or not lines[0].startswith('---\ntitle'):
                # 打开文件并读取全部内容
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                # 在文件开头插入指定内容
                new_content = f"---\ntitle: {file_name[:-3]}\ndate: {current_time}\ntags:\n---\n{content}"

                # 写入新内容到文件
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(new_content)

                print(f"Added content to file: {file_path}")
            else:
                print(f"Skipped file: {file_path} (already contains specified content)")

# 调用函数来添加内容到文件
add_content_to_files()
