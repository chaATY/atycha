---
title: CSGO 辅助思路 & VAC 保护分析
date: 2023-11-26
author: CHA.ATY
environment:
  - Windows10-22H2_19045.3570
tags:
  - Game
---

# 一、地址寻找

既然是实现辅助，那我们必然要对游戏中一些内存的值做读写，而实现读写的前提是我们知道它们在内存中的地址。所以做辅助前需要花大量的时间去寻找我们所需变量在内存中的地址。

寻找地址是一项极为枯燥繁琐的工作，大体思路是控制游戏的一些可变量，使其改变或者不变，同时搜索内存中发生改变或者不变的值，以此来缩小筛选范围

PS: 地址搜索一定要通过 `csgo.exe -insecure` 不安全模式运行游戏，这样游戏不会去连接VAC服务器执行安全策略，特别是当CE还是用的官网版不是魔改版的情况下，一定不要头铁去官匹搜内存。不然分分钟你就变成封号斗罗（不要问我为什么这么清楚）

## 1.查找视野矩阵

当我们进行游戏时，准星处其实是一个视野矩阵，当我们跳一下时会发现上下左右四个点会向外扩展，静步时会向内收缩。找到这个矩阵在内存中存在的位置是实现自瞄的关键。
![](网络安全-GameSecurity/res/41.png)

这个矩阵在内存中是以浮点数的二维数组形式表示，并且其不会随着人物移动而改变，只有控制准星的移动，它的值才会改变。根据这个特性，我们可以使用CE搜索浮点数内存将变量筛选到100个
![](网络安全-GameSecurity/res/42.png)

然后视野矩阵还有个特征，就是在不开镜的情况下，其首元素值只会在 -1 ~ 1 之间，开镜后其值会大于1。根据这个特征，搜索 -1.5 ~ 1.5间的浮点数，可以再度收缩筛选范围。而后拿狙击枪开镜再筛选一次，就可以将筛选范围降的很低了。接下来对剩下的几个地址右键浏览相关内存区域，可以看到当我们准星移动时，该内存数值一直在发生变化，当我们准星不移动时该内存不变。这样就可以确认我们成找到了视野矩阵地址
![](网络安全-GameSecurity/res/43.png)

并且可以看到这个地址是绿色的，也就是说其本身就是基址，那记录下来就可以了，不需要再费工夫去找它的基址了

## 2.查找自己角度

相比于查找视野矩阵来说，查找自己角度又要简单很多了。对于这类沙盒游戏，其实只需要一个表示左右的角度和一个表示上下的角度就可以表示全部的方向了。 查找方法于前面类似，通过找改变角度查找变动的浮点数即可得到。

同时，CSGO的角度查找还有一个特征，当准星指向最上方的时候，上下角度角度值为-89，当准星指向最下方的时候，上下角度的角度值为89。通过这个特征，就能很容易的确定角度指针
![](44.jpg)

## 3.查找自己坐标值

同样的，既然是个沙盒游戏，其本身其实就是模拟了一个三位空间，那必然有变量表示着我当前的X Y Z的坐标值。我们可以通过敌人坐标值与我们坐标值做运算得到与敌人的相对距离，即自瞄距离。

这个坐标值的寻找也非常容易，就是控制自己的移动与不移动来用CE查找变动与不变动的浮点数
![](网络安全-GameSecurity/res/45.png)

## 4.查找敌人与队友的信息

这个信息的查找应该就是整个外挂实现最重要的部分了，因为得到了敌人的结构体，我们就能得到关于敌人血量、护甲、武器、坐标值在内的大量信息。按常理，敌人指针应该是非常难找的，但CSGO给我们提供了一个非常好用的工具————“开发者控制台”。通过这个神器，我们可以控制机器人的动与不动，进而搜索得到机器人的XYZ坐标值，再上推出角色结构体

首先先用指令 “bot_kick”踢出所有机器人，然后用 “bot_add” 指令增加一个敌方机器人，接着通过 “bot_stop” 这条指令控制机器人的移动与不移动，通过CE搜索改变与不改变的浮点数值。然后还可以自己与机器人站在一起，通过自己的坐标判断机器人坐标的大致范围，进行数值筛选
![](网络安全-GameSecurity/res/46.png)

筛选到这一步其实已经很难通过控制机器人是否移动再来筛选了，但是还是会发现列表中有许多相差很近的数值，一般认为这是敌人某些骨骼的坐标值，所以我们可以通过浏览内存区域功能来判断出敌人这个值是敌人本身的XYZ坐标值还是骨骼的XYZ坐标值。（骨骼XYZ坐标值往往是连成一片的，而敌人本身的XYZ坐标值则是连续的三个浮点变量）
![](网络安全-GameSecurity/res/47.png)

其中还可以看到一个带绿字的地址，根据前面找自身XYZ坐标时的经验可以知道server.dll这个位置保存着所有角色的XYZ坐标值，我们可以通过这个值拿到敌人的XYZ坐标，然后以这个坐标值为筛选条件筛掉一部分骨骼地址
![](网络安全-GameSecurity/res/48.png) ![](网络安全-GameSecurity/res/49.png)

然后就是漫长的、枯燥乏味的搜索，如果运气好，能很快找到这样一个地址
![](网络安全-GameSecurity/res/50.png)

这个 “client.dll+4D523AC”这个地址非常眼熟，在前面搜索自身的XYZ值时可以看到其机制为 “client.dll+4D5239C”，它们直接仅相差了0x10的偏移。这里可以有一个大胆的猜想，游戏将所有的玩家实例基址做到了一个数组里，并且每个玩家的基址相差0x10

为了验证这个猜想，再添加了2个机器人，然后用CE的结构分析工具观察“client.dll+4D5239C”这个数组，可以看到，数组里有4个成员了
![](网络安全-GameSecurity/res/51.png)

可以跟入这些指针，可以看到包括生命值、护甲、金钱、坐标值、阵营标识在内的所有信息，并且偏移值均相同，说明用于初始化他们的类是同一个。至此，我们得到了该局游戏所有玩家的数组

## 5.查找敌人骨骼

虽然根据前面的方法，我们得到了敌人的坐标，已经可以计算角度实现方框透视和自瞄了，但是如果希望实现骨骼透视和锁头，还需要得到敌人的骨骼坐标。

先来解释一下骨骼是什么，在这类3D游戏的建模中，为了实现人物模型的可变化，一个人物模型其实是由多个模型共同组成的，头、手、腿、脚、身体等都是不同的模型，将他们拼装在一起在是一个人物的完整模型。这样的设计模式可以实现各个骨骼的各自移动，让人物看起来更真实自然。因此，每块骨骼都应该具有一个独立的坐标点，我们得到了其中某些骨骼的坐标点，才可以实现出骨骼透视和锁头。

其实大家应该已经猜到，在前面搜索敌人坐标点时，看到的很多极为相近的数值，就应该是某些骨骼的坐标点，那我们现在要做的就是搜索敌人骨骼结构体的地址。 搜索骨骼地址，有个非常关键的技巧就是，当我们看向或者靠近敌人的时候，敌人的骨骼坐标就会发生变动，而当我们远离且不看向敌人时，这个值就不变。这其实是游戏在模拟敌人呼吸而产生的全身器官的轻微摆动。 通过这一特征，我们可以用指令禁止掉机器人的行动，然后控制自己看向或不看向敌人来搜索变动或不变动的浮点数。

成功找到后，看向敌人时CE浏览内存应该显示这样的图案，可以看到，下面这个数组均带XYZ坐标值，并且都在浮动
![](网络安全-GameSecurity/res/52.png)

而当我们离敌人有一段距离且不看向敌人时，这块内存区域的值就不变
![](网络安全-GameSecurity/res/53.png)

这样就成功找到了敌人骨骼结构体的地址，然后回溯找基址，就会发现在敌人角色结构体的某一偏移处保存着这一地址，那就说明成功找对了。角色结构体保存着血量、护甲、金钱、阵营标识、骨骼地址等等于该角色有关的信息，并且由一个列表保存着每个角色实例的指针，一切的逆向分析的结果都非常合理，说明我们成功得到了我们需要实现外挂功能的所有信息，下面就可以进行外挂的实现了。

---

# 二、外置挂制作

外置挂指的是外挂模块并不注入到游戏进程空间内，而仅仅作为一个外部的进程通过其他的手段来读写游戏进程内存。在CSGO游戏的外置挂中，主要表现为创建一个透明窗体并覆盖在游戏窗体上，通过外部的内存读写读取到敌人的信息，然后在透明的窗体上绘制出敌人纹理实现透视。同样的，因为涉及透明窗体的创建，游戏可以通过枚举窗体来发现这个用于纹理绘制的透明窗体的存在。截至至2020年11月（写这篇博客时），CSGO官匹还没有启用窗体枚举的检测，但是基于5E、BE等平台的CSGO启用了这个检测，因此正常来说这个方法仅限于CSGO官匹的作弊。 这里先附张效果图
![](网络安全-GameSecurity/res/54.png)

运行外挂后可以看到生成了一个窗体名为随机字符串的透明窗体
![](网络安全-GameSecurity/res/55.png)

对于CSGO来说外置挂的核心就是透明窗体的创建，可以设计一个窗口覆盖类来完成窗体的初始化和绘制等一系列操作

```cpp
/*
窗口覆盖类
*/

class Overlay
{
private:
	IDirect3D9* m_IDirect3D9;
	IDirect3DDevice9* m_IDirect3DDevice9;

	ID3DXLine* m_ID3DXLine;
	ID3DXFont* m_ID3DXFont;

	D3DPRESENT_PARAMETERS m_D3DPRESENT_PARAMETERS;

	HWND m_hwnd;
	HWND m_game;


	/* 随机化字符串 */
	char* random_string()
	{
		static std::vector<char> maps{ 'q','w','e','r','t','y','u','i','o','p','l','k','j','h','g','f','d','s','a','z','x','c','v','b','n','m','Q','A','Z','W','S','X','E','D','C','R','F','V','T','G','B','Y','H','N','U','J','M','I','K','O','L','P','1','2','3','4','5','6','7','8','9','0' };
		static char buffer[100]{ 0 };

		srand((unsigned)time(nullptr));
		for (int i = 0; i < 30; i++) buffer[i] = maps[rand() % maps.size()];
		return buffer;
	}

	/* 窗口过程 */
	static LRESULT CALLBACK window_process(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		static MARGINS margins{ 0 };

		switch (uMsg)
		{
		case WM_CREATE:
			DwmExtendFrameIntoClientArea(hWnd, &margins);
			return 1;
		case WM_CLOSE:
			PostQuitMessage(0);
			return 1;
		case WM_HOTKEY:  // 这里可以设置热键行为
			return 1;

		}
		return DefWindowProcA(hWnd, uMsg, wParam, lParam);
	}

public:
	Overlay(HWND hWnd) : m_game(hWnd) {}
	~Overlay() {}

	/* 创建一个透明窗口 */
	bool create_overlay_window()
	{
		char sz_class[100]{ 0 }, sz_title[100]{ 0 };
		strcpy(sz_class, random_string());
		strcpy(sz_title, random_string());

		WNDCLASSEXA window_class{ 0 };
		window_class.cbSize = sizeof(window_class);
		window_class.hCursor = LoadCursor(0, IDC_ARROW);
		window_class.hInstance = GetModuleHandle(NULL);
		window_class.lpfnWndProc = window_process;
		window_class.lpszClassName = sz_class;
		window_class.style = CS_VREDRAW | CS_HREDRAW;
		if (RegisterClassExA(&window_class) == 0)
		{
			MessageBoxA(nullptr, "RegisterClassExA", "错误", MB_OK | MB_ICONHAND);
			exit(-1);
		}

		RECT rect{ 0 };
		GetWindowRect(m_game, &rect);
		int x = rect.left;
		int y = rect.top;
		int width = rect.right - rect.left;
		int height = rect.bottom - rect.top;
		if (GetWindowLongA(m_game, GWL_STYLE) & WS_CAPTION)
		{
			x += 8;
			width -= 8;
			y += 30;
			height -= 30;
		}

		m_hwnd = CreateWindowExA(WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED,
			sz_class, sz_title, WS_POPUP, x, y, width, height, NULL, NULL, GetModuleHandle(NULL), NULL);
		if (m_hwnd == NULL)
		{
			MessageBoxA(nullptr, "CreateWindowExA", "错误", MB_OK | MB_ICONHAND);
			exit(-1);
		}

		SetLayeredWindowAttributes(m_hwnd, 0, RGB(0, 0, 0), LWA_COLORKEY);
		UpdateWindow(m_hwnd);
		ShowWindow(m_hwnd, SW_SHOW);

		return true;
	}

	/* 消息循环 */
	void message_handle()
	{
		MSG msg{ 0 };
		while (msg.message != WM_QUIT)
		{
			if (PeekMessageA(&msg, 0, 0, 0, PM_REMOVE))
			{

				TranslateMessage(&msg);
				DispatchMessageA(&msg);
			}
			else
			{
				RECT rect{ 0 };
				GetWindowRect(m_game, &rect);
				int x = rect.left;
				int y = rect.top;
				int width = rect.right - rect.left;
				int height = rect.bottom - rect.top;
				if (GetWindowLongA(m_game, GWL_STYLE) & WS_CAPTION)
				{
					x += 8;
					width -= 8;
					y += 30;
					height -= 30;
				}

				MoveWindow(m_hwnd, x, y, width, height, TRUE);

				do_cheat();
				
			}
		}

		UnregisterHotKey(NULL, HotKeyId);
		GlobalDeleteAtom(HotKeyId);
	}

  	/* 初始化 */
	bool initialize()
	{
		m_IDirect3D9 = Direct3DCreate9(D3D_SDK_VERSION);
		if (m_IDirect3D9 == nullptr)
		{
			MessageBoxA(nullptr, "Direct3DCreate9", "错误", MB_OK | MB_ICONHAND);
			exit(-1);
		}

		memset(&m_D3DPRESENT_PARAMETERS, 0, sizeof(m_D3DPRESENT_PARAMETERS));
		m_D3DPRESENT_PARAMETERS.Windowed = TRUE;
		m_D3DPRESENT_PARAMETERS.SwapEffect = D3DSWAPEFFECT_DISCARD;
		m_D3DPRESENT_PARAMETERS.BackBufferFormat = D3DFMT_UNKNOWN;
		m_D3DPRESENT_PARAMETERS.EnableAutoDepthStencil = TRUE;
		m_D3DPRESENT_PARAMETERS.AutoDepthStencilFormat = D3DFMT_D16;
		m_D3DPRESENT_PARAMETERS.PresentationInterval = D3DPRESENT_INTERVAL_ONE;
		HRESULT result = m_IDirect3D9->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, m_hwnd, D3DCREATE_HARDWARE_VERTEXPROCESSING, &m_D3DPRESENT_PARAMETERS, &m_IDirect3DDevice9);
		if (result != D3D_OK)
		{
			MessageBoxA(nullptr, "CreateDevice", "错误", MB_OK | MB_ICONHAND);
			exit(-1);
		}

		result = D3DXCreateLine(m_IDirect3DDevice9, &m_ID3DXLine);
		if (result != D3D_OK)
		{
			MessageBoxA(nullptr, "D3DXCreateLine", "错误", MB_OK | MB_ICONHAND);
			exit(-1);
		}

		result = D3DXCreateFontA(m_IDirect3DDevice9, 20, 0, FW_DONTCARE, D3DX_DEFAULT, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, DEFAULT_QUALITY, FF_DONTCARE, "Arial", &m_ID3DXFont);//Arial Vernada
		if (result != D3D_OK)
		{
			MessageBoxA(nullptr, "D3DXCreateFontA", "错误", MB_OK | MB_ICONHAND);
			exit(-1);
		}

		g_client = GameControler.FindModule("client.dll");
		g_engine = GameControler.FindModule("engine.dll");
		g_server = GameControler.FindModule("server.dll");
		return true;
	}

	void do_cheat() {   // 作弊函数
    ... ...
  }
  void render(struct player_list* players) {...}    // 渲染函数
```

有了这个透明窗体就可以用各种D3DX函数来绘制纹理了
```cpp
	/* 渲染矩形 */
	void render_rect(float x, float y, float width, float height, D3DCOLOR color = D3DCOLOR_ARGB(255, 0, 0, 255), float size = 1.0f)
	{
		D3DXVECTOR2 vextor[5]{ {x,y},{x + width,y},{x + width,y + height},{x,y + height},{x,y} };
		m_ID3DXLine->SetWidth(size);
		int nRet =  m_ID3DXLine->Draw(vextor, 5, color);
	}

	/* 渲染文本 */
	void render_text(long x, long y, const char* text, D3DCOLOR color = D3DCOLOR_ARGB(255, 0, 0, 255))
	{
		RECT rect{ x,y };
		m_ID3DXFont->DrawTextA(nullptr, text, -1, &rect, DT_CALCRECT, color);
		m_ID3DXFont->DrawTextA(nullptr, text, -1, &rect, DT_LEFT, color);
	}

	/* 渲染线段 */
	void render_line(float left, float top, float right, float down, D3DCOLOR color = D3DCOLOR_ARGB(255, 0, 0, 255), float size = 1.0f)
	{
		D3DXVECTOR2 vextor[2]{ {left,top},{right,down} };
		m_ID3DXLine->SetWidth(size);
		m_ID3DXLine->Draw(vextor, 2, color);
	}
```

而对于敌人信息的获取，可以定义一个玩家结构体，然后循环从角色结构列表中读取玩家各项信息的内存并保存到玩家结构体列表中
```cpp
const int g_players_count = 32; // 游戏玩家数量
struct player_list
{
	bool effective;//是否有效
	int aimbot_len;//自瞄长度
	bool self;//是自己
	float location[3];//身体位置
	float head_bone[3];//头骨位置
	int camp;//阵营
	int blood;//血量
	int entity_glow_index; // 辉光index
	DWORD BoneMatrix;      // 骨骼基地址
	DWORD SpottedByMask;   // 敌人是否可见
	float distance;        // 与我的距离
};

extern CGameControler GameControler;

//获取玩家列表
void get_player_list(struct player_list* players)
{
	system("cls");    // 起一个终端  方便输出数据调试

	DWORD local = GameControler.read<DWORD>(g_client + dwLocalPlayer);
	DWORD health = GameControler.read<int>(local + m_dwHP);
	DWORD selfTeamNum = GameControler.read<int>(local + m_dwTeamNum);    //自己的阵营序号

	DWORD EntityList = g_client + dwEntityList;
	for (int i = 0; i < g_players_count; i++)
	{
		DWORD player_base_address = GameControler.read<DWORD>(EntityList + i * 0x10);
		
		if (player_base_address == 0) continue;   // 链表结构  此节点为0后面必为空

		players[i].blood = GameControler.read<DWORD>(player_base_address + 0x100);
		if (players[i].blood <= 0) continue;

		players[i].effective = true;
		players[i].aimbot_len = 9999;

		if (GameControler.Read((LPCVOID)(player_base_address + m_dwBoneMatrix), &players[i].BoneMatrix, sizeof(DWORD)))
		{
			GameControler.Read((LPCVOID)(players[i].BoneMatrix + 99 * sizeof(float)), &players[i].head_bone[0], sizeof(float));
			GameControler.Read((LPCVOID)(players[i].BoneMatrix + 103 * sizeof(float)), &players[i].head_bone[1], sizeof(float));
			GameControler.Read((LPCVOID)(players[i].BoneMatrix + 107 * sizeof(float)), &players[i].head_bone[2], sizeof(float));
		}
		GameControler.Read((LPCVOID)(player_base_address + m_vecOrigin), players[i].location, sizeof(players[i].location));
		GameControler.Read((LPCVOID)(player_base_address + m_dwTeamNum), &players[i].camp, sizeof(int));
		GameControler.Read((LPCVOID)(player_base_address + m_bDormant), &players[i].Dormant, sizeof(BYTE));
		GameControler.Read((LPCVOID)(player_base_address + dwGlowIndex), &players[i].entity_glow_index, sizeof(int));
		GameControler.Read((LPCVOID)(player_base_address + m_dwSpottedByMask), &players[i].SpottedByMask, sizeof(DWORD));
		// 设置己方阵营
		if (players[i].camp == selfTeamNum)	players[i].self = true;
		else  players[i].self = false;
		// 计算玩家与我的距离
		players[i].distance = sqrt(pow(players[i].location[0]-players[0].location[0], 2) + pow(players[i].location[1] - players[0].location[1], 2) + pow(players[i].location[2] - players[0].location[2], 2));

		//if(players[i].camp != players[0].camp)
		//	printf("玩家ID：%d \t 阵营表示：%d\t 是否休眠：%d\n", i, players[i].camp, players[i].Dormant);
	}
}
```

这里我还封装了一个 GameControler 类，用于实现诸如：游戏Pid获取、权限令牌获取、进程句柄获取与管理、游戏窗体句柄获取、游戏模块基址获取、读写内存等每个游戏辅助都需要的接口，这样每次只需要包含一下这个头文件，实例化的时候指定一下游戏进程名就可以了。然后我还封装了一个 GameControlerByDriver 类，里面的函数具有和 GameControler 类完全相同的函数原型，不同之处在于这个类不会去获取游戏句柄，而是直接打开驱动读写内存，可以在很大程度上绕过游戏在ring3层的保护。同时，因为具有相同的函数原型，在切换时只需要更换一下头文件的名字就可以了，不需要修改任何代码。

对于游戏内大量偏移地址的管理，我的建议是写成一个头文件来统一管理。不然都吧地址直接写在代码里，游戏一更新，偏移一变，修改更新起来会非常非常麻烦
```cpp
// offset.hpp
#pragma once

constexpr DWORD dwBaseXYZ = 0xxxxx;    // [server.dll + 0xxxx]
constexpr DWORD dwX = 0xxxx;             // [dwBaseX + 0xxxx]   float
constexpr DWORD dwY = 0xxxx;             // [dwBaseY + 0xxxx]   float
constexpr DWORD dwZ = 0xxx;             // [dwBaseZ + 0xxxx]   float
constexpr DWORD dwViewMatrix = 0xxxxxx; // [client.dll+xxxxx] 视野矩阵
```

---

# 三、游戏保护分析（重要）

游戏保护分析才是最头疼最难的部分，因为保护这东西…稍不留神就会变成“封号斗罗”，而且payload逆向难度也是非常高。所以我实现外挂功能之前都会先去搜索网络上有关这个游戏保护的分析文章，根据里面的思路绕过游戏的保护，先将整体的外挂功能实现出来。然后再慢慢花时间去研究游戏的保护（因为对游戏保护的分析确实是费时费力的活）

## 1.查壳

常规套路首先肯定要先查壳
![](网络安全-GameSecurity/res/56.png)

其他dll也可以按这种方法看一下，可以看到都是不带壳的。其实很多程序都是不带壳的，因为加了强商业化壳会极大的影响游戏性能，因为强壳普遍都会插入大量的垃圾代码和虚拟机（比如某PUBG加什么垃圾壳FPS直线下降

## 2.ARK检查Hook

查完壳之后按常规套路用ARK攻击检查游戏Hook了哪些API。

对于游戏Hook掉的API我们可以直接分析它把API勾到了哪里，交叉引用可以找到游戏保护payload的位置，而对于游戏没有Hook的API，我们可以去Hook它，看游戏在哪个位置调用了这个API。 

然后最好不要对游戏hook的api再做hook，毕竟你hook他、他hook你，这动静可能有点大，而且它都hook了，很大可能会对这个api做堆栈回溯检测，你再hook它相当于是你的函数调用了这个api被他检测到了，这可能直接就会ban你
![](网络安全-GameSecurity/res/57.png)

搜了一圈，可以看到，游戏Hook了很多API，但其中敏感API只有少数几个。 可以看到了游戏大部分的钩子指向的都是 _GameOverlayRenderer.dll_ 这个模块，但是可以看到，这个Hook指向的模块是GameOverlayRenderer.dll，观察这个模块的路径会发现它都不隶属于CSGO这个款游戏，而是直接位于steam文件夹下的，这基本可以反映这是steam提供给游戏的渲染模块，Hook到这个模块上的API基本都不用分析了，一般都是游戏引擎为了实现更丰富的功能而接管的API进行的操作。

然后我们可以看到游戏Hook了PeekMessageW，这个API是windows用于实现消息获取的，很多游戏都会通过Hook这个API实现游戏引擎接管消息系统，这个位置被Hook了，我们基本就没法用PostMessage SendMessage这一类API去实现模拟按键一类的操作

然后还可以看到游戏Hook了 LoadLibarayExW 函数，这个函数导出给LoadLibrary API，这个函数用于加载模块到游戏进程中，如果这个Hook是检测API调用，那很可能意味着游戏检测到远线程注入式的模块注入行为。 关于这一点我们先埋个伏笔，这个位置很细节，是一套组合拳，后面会详细介绍

## 3.调试器检测

看完Hook列表后，就可以去勾一些游戏没用勾的API做行为感知。这里勾的方法有很多，最常用的是IAT Hook，inline Hook，这两种方法各有利弊。IAT Hook操作简单，但是它仅仅能勾住指定的一个模块，如果是exe加载了别的模块，那个模块调用了API，IAT Hook对这种行为无能为力。

Inline Hook操作会复杂一些，特别对于x86和x64，Hook的方法相差略大，但是它能勾住整个进程的API调用行为，但同时，它也有个很大的缺点，就是动静很大，即Hook的这个行为很容易被发现。因为用InlineHook做API行为感知，我们往往勾的是Ntdll模块，而游戏对于这个模块可以说是高敏感的，游戏自身也会去勾很多这个模块的API，所以这个方法虽然好用，但还是谨慎一点，一定不要用大号去整这些活

对于IAT Hook和Inline Hook的缺点，其实三环已经没有很好的解决方案了，要整只能从0环下手了。0环骚操作还是很多的，比如可以勾入口点（KiFastSystemCall），Ntdll里的Zw函数基本传一个系统调用号，然后通过系统全局共享内存0x7FFE0300调用KiFastSystemCall进入内核，我们可以直接Hook KiFastSystemCall这个入口点做行为感知。 再底层一点，那就是直接勾系统调用表，也就是SSDT Hook。 0环的优势就是极大的降低被检测的风险，但同样要为此付出很高的成本。 而且，在x64的windows下，不管是Hook KiFastSystemCall还是Hook SSDT，都会触发Patch Guard检测而引起BSOD，所以说0环的API检测，成本可以说是非常高

这里还可以再提一句，对于API调用的行为感知，还可以借助现成工具，比如 _API Monitor_ 这一类工具。我看以前关于CSGO的分析文章，是有师傅借助这款工具做分析的，但是这两天根据我的实践发现用不了，监听不到关于游戏的任何API调用，应该是游戏保护模块做了一些魔幻操作阻止了该工具的监听，问了一些大师傅，师傅们说大部分的游戏都会组织这一类工具做API的监听，所以最好还是自己实现一些Hook框架做行为感知分析

然后我说一下我的API行为感知模块设计思路：通过注入一个Dll在 _DLL_PROCESS_ATTACH_ 时Hook掉指定的API，将他们勾到自己封装的函数上，通过[ebp + 4]寻址得到调用这个API的位置（如果不知道为什么是[ebp + 4]建议去复习汇编），得到返回地址然后记录到文件里。这种行为其实是非常暴力的，因为写文件这个过程非常耗资源，所以勾完之后基本是没法正常玩游戏的，后期可以考虑用哈希表优化写日志的过程
![](网络安全-GameSecurity/res/58.png)

我这里勾住了IsDebuggerPresent API，可以看到，短短60秒的时间内游戏调用了这个API接近两万次，可以确定至少有一个线程在循环调用API做调试器检测。去重后可以看到三条记录

```log
Now is 2020/11/28 17:30:50 Call IsDebuggerPresent	addr: 55a7eb86
Now is 2020/11/28 17:30:53 Call IsDebuggerPresent	addr: 56025a26
Now is 2020/11/28 17:31:34 Call IsDebuggerPresent	addr: 55a847fa

PS：我是以-insecure离线方式启动的游戏，所以这算是不完全检测，大家对这个数据仅供参考
```

然后我们去静态看下这是什么位置
![](网络安全-GameSecurity/res/59.png)

可以看到，有关IsDebuggerPresent这个API的所有调用均来自这两个DLL。通过这一点，我们可以马上锁定，这两个模块是CSGO这款游戏的安全保护模块（是但不限于），接下来我们可以静态分析一下
![](网络安全-GameSecurity/res/60.png)

这里我dump出模块，rebase后跳到log记录的触发地址上可以看到有大量的调用
![](网络安全-GameSecurity/res/61.png)

但处理结果都是相似的，即如果发现调试器附加，做一下记录然后抛出 _int 3_ 中断

这基本上就是我对游戏调用API行为感知的一个完整过程，下面的API也基本是这种方法

**Hook CheckRemoteDebuggerPresent**: 未发现调用

## 4.硬件断点检测

**Hook NtGetContextThread**: 未发现调用

## 5.堆栈回溯检测

**Hook RtlCaptureStackBackTrace**: 未发现调用

## 6.反注入

记得前面我们说游戏Hook了LoadLibarayExW函数实现了反注入，并且对比了离线模式游戏，可以发现离线模式启动的游戏不存在这个钩子。 这里我们先不对这个钩子做处理，直接向游戏中注入我的Hook模块
![](网络安全-GameSecurity/res/62.png) ![](网络安全-GameSecurity/res/63.png)

可以看到，第一次点击注入，注入器上显示注入失败，但是我马上再次输入，注入器都是提示注入成功，并且返回是句柄全部都是一模一样的，而且在ARK工具上无法看到我们注入的InlineHook这个模块
![](网络安全-GameSecurity/res/64.png)

注入器判定一个模块是否注入成功仅仅是判断LoadLibrary函数的返回值是否为真和线程是否正常结束，而这两点都为真但是模块并没有真正的进去，首先想到的就是被Hook的函数干掉了，我们回过头来分析这个Hook指向的函数。 从ARK工具上可以看到钩子指向的函数是 _csgo.exe + 0xA980_, dump出模块或者直接IDA加载csgo.exe，Rebase基址后可以轻易找到这个函数
![](网络安全-GameSecurity/res/65.png)

可以看到，在这个函数中会将Dll路径和Dll模块大小送入sub_40C5F0函数，然后跟进这个函数调了一下
![](网络安全-GameSecurity/res/66.png)

刚开始我以为分析到这里就可以了，这个全局数组保存的应该就是允许加载的DLL，只有存在于这个数组的DLL在可以被加载，直到我dump出了这个数组一看才知道远没有这么简单。 这个数组的偏移是 “csgo.exe + 0x76944” 我用CE直接跳进去看一眼
![](网络安全-GameSecurity/res/67.png)

好家伙，这是啥，这不就是我的InlineHook模块吗。又反复看了几遍这个列表的交叉引用并dump整个数组对比了一番，发现任何尝试加载到游戏进程的DLL，不论加载成功与否，都会被写入这个列表中，下次再尝试加载就不会去调用真正的LoadLibrary API，而是直接给你返回一个模块句柄，而若这个模块之前并没有成功的被加载到进程内，则也会给你返回一个无效的句柄。这也就是为什么前面注入时，第一次注入失败，后面再注入就会提示成功但是自始至终我们的DLL都没有出现在模块列表中的原因。 CSGO这样Hook这个API，等于是将LoadLibrary这个API做了一次封装，既实现了加载DLL的功能，又实现了从进程获取模块句柄的功能，而不会导致重复注入。（这一手操作我直接喊好家伙）

但是可以发现，我们并没有找到真正的模块反注入代码。跟人FAKE_LoadLibrary后会进GameOverlayRenderer.dll的一个函数直接分发到KernelBase.dll的一段gadget上。我通过对module_list列表下读写断点并回溯找到了这个位置
![](网络安全-GameSecurity/res/68.png)

这个函数其实就是NtOpenFile的钩子函数，前面看ARK扫描结果的时候我还纳闷Hook NtOpenFile函数有什么用，其实游戏利用的就是LoadLibrary会调用NtOpenFile打开Dll这个逻辑来Hook NtOpenFile实现反注入。那我们修复NtOpenFile的钩子，就可以直接对游戏实现远线程注入式的模块注入了 这里贴个CE脚本demo
```cpp
[ENABLE]
//code from here to '[DISABLE]' will be used to enable the cheat
NtOpenFile:
db B8 33 00 00 00

[DISABLE]
//code from here till the end of the code will be used to disable the cheat
NtOpenFile:
db E9 95 E5 F4 FF
```

## 7.进程枚举

**HOOK CreateToolhelp32Snapshot, Process32Next**:

发现来自steamclient.dll模块的调用
![](网络安全-GameSecurity/res/69.png)

## 8.模块枚举

**HOOK CreateToolhelp32Snapshot, Module32Next**: 未发现相关调用

## 9.线程枚举

**HOOK CreateToolhelp32Snapshot, Thread32Next**: 未发现相关调用

## 10模块检测

**HOOK GetModuleFileNameA**:

发现游戏调用并尝试获得模块名称
![](网络安全-GameSecurity/res/70.png)

但是来回钩了好多次也换了很多中注入方式好像这个位置都没有尝试去拿我注入进去模块的句柄，也来回看了几次这个地址处的汇编，感觉不像是游戏保护

### **驱动枚举**

ARK工具未发现CSGO加载驱动，这种类型检测可能性很小

### **总结**

官匹CSGO的保护还是非常薄弱的，仅仅只有一些非常基础的调试器检测和钩子反注入。 但通过我们定位到的游戏保护模块 tier0.dll和tier0_s.dll可以发现大量大量的检测API的交叉引用。但是在游戏运行过程当中发现只有极少数的几个被调用。 通过这一点可以确定CSGO游戏预留了大量的安全方案，它们可能会在一些特定的场合下动态开启

CSGO官匹保护的分析也花费了我很多的时间，但是根据我的分析结果来看，与网络上其他大佬的分析文章有一定的出入。 首先我不管在离线模式还是在官匹在线模式下都没有发现游戏有调用 _RtlCaptureStackBackTrace_ API做堆栈回溯检测；我也没有发现游戏通过反射DLL的模式加载检测payload 不知道是我的分析方法问题还是游戏安全保护方案做了修改