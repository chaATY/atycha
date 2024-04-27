
1. 获取当前最顶层的界面的信息
   
    adb shell "dumpsys activity top | grep ACTIVITY | tail -n 1"

    adb shell "dumpsys window | grep mFocus | grep -Ei ACTIVITY | tail -n 1"

    dumpsys activity top :打印顶层Activity信息

    grep ACTIVITY：从上个命令结果中过滤出Activity相关信息

    tail -n 1：从上一步过滤结果中继续过滤出最后一条记录，也就是当前界面(顶层top)activity

2. 当前获取焦点的窗口

    adb shell dumpsys activity activities | grep "mCurrentFocus=Window"

3. 获取应用安装路径

    adb shell pm path <package_name>

4. 查看当前窗口（显示包名）

    adb shell dumpsys window | grep mCurrentFocus
    
5. 查看当前是否在锁屏
   
    adb shell dumpsys window policy | grep mIsShowing

6. 查看当前进程和窗口信息
   
    adb shell dumpsys window windows |grep "Window #"

7. 调试查看ActivityManagerService相关属性详解
   
    adb shell am stack list

8. 判断手机是user版本还是debug版本
   
    adb shell getprop ro.build.type

9.  查看apk版本
    
    adb shell dumpsys package com.zui.launcher | grep versionName

10. 查看apk对应包名
    
    adb shell pm list packages -f

adb shell getprop | grep build.date

adb shell getprop | grep build.display

adb shell dumpsys package com.lenovo.lsf.device

adb shell dumpsys SurfaceFlinger

adb shell screencap -p /sdcard/screen.png

adb shell dumpsys SurfaceFlinger

adb shell dumpsys battery set usb 0

adb shell settings get system tian_jiao_face_ids

adb shell content query --uri content://com.fujitsu.mobile_phone.HumanCentricSettings.SettingProvider/gender
adb shell content query --uri content://com.fujitsu.mobile_phone.HumanCentricSettings.SettingProvider/birth
adb shell content query --uri content://com.fujitsu.mobile_phone.HumanCentricSettings.SettingProvider/height
adb shell content query --uri content://com.fujitsu.mobile_phone.HumanCentricSettings.SettingProvider/weight

# 屏幕截图

adb exec-out screencap -p > sc.png

如果 adb 版本较老，无法使用 exec-out 命令，这时候建议更新 adb 版本。无法更新的话可以使用以下麻烦点的办法：

adb shell screencap -p /sdcard/sc.png

adb pull /sdcard/sc.png

# 录制屏幕

adb shell screenrecord /sdcard/filename.mp4

需要停止时按 Ctrl-C，默认录制时间和最长录制时间都是 180 秒。

如果需要导出到电脑：

adb pull /sdcard/filename.mp4

adb shell dumpsys SurfaceFlinger > SurfaceFlinger.txt