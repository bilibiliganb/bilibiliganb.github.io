import os
import re

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
