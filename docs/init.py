import os

# 获取当前目录下的所有文件夹
folders = [folder for folder in os.listdir('.') if os.path.isdir(folder)]

# 遍历所有文件夹
for folder in folders:
    if folder.endswith('.assets'):
        new_folder = folder.replace('.assets', '')
        os.rename(folder, new_folder)
        print(f'Renamed folder: {folder} -> {new_folder}')


