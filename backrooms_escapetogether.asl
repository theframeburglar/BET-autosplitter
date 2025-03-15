/*
==Backrooms: Escape Together Autosplitter==
	Authored by Frogfucius
		Thanks to Reokin for the Match State variables :)

==Documentation Notes==

	Better and more general documentation for LiveSplit autosplitters can be found at https://github.com/LiveSplit/LiveSplit.AutoSplitters/blob/master/README.md
	Timer code can be found at https://github.com/LiveSplit/LiveSplit/blob/master/LiveSplit/LiveSplit.Core/Model/TimerModel.cs

	"vars" is a persistent object that is able to contain persistent variables
	"old" contains the values of all the defined variables in the last update
	"current" contains the current values of all the defined variables
	"settings" is an object used to add or get settings 
*/

state("betgame-Win64-Shipping", "0.8.0+")
{

}

startup
{
	//settings.Add("disable_restart_time_removal", false, "Disable pausing of autosplitter when restarting levels");
}

init
{
	game.Suspend();
	
	// Latent action UUIDs to check
	// Keep last one as 0 so we know when to stop
	// 0.8.0 - escape level_run
	// sp 0000000095F6E373
	// sp 000001FA26A9C400 
	var UUIDs = new ulong[] {0x0000000095F6E373, 0};
	vars.arrUUIDs = game.AllocateMemory(8 * UUIDs.Length);
	
	for (int i = 0; i < UUIDs.Length; i++)
	{
		memory.WriteValue<ulong>((IntPtr)vars.arrUUIDs + (i * 8), UUIDs[i]);
	}
	
	vars.watchers = new MemoryWatcherList();
	vars.MainMenuAddr = game.AllocateMemory(40);
	vars.Level_0Addr = game.AllocateMemory(40);
	vars.MainMenu = "/Game/Maps/BR_MainMenu/BR_MainMenu";
	vars.Level_0 = "/Game/Maps/MainLevels/Level_0/Level_0";
	for (int i = 0; i < vars.MainMenu.Length; i++)
	{
		memory.WriteValue<byte>((IntPtr)(vars.MainMenuAddr + (i * 2)), (byte)vars.MainMenu[i]);
		memory.WriteValue<byte>((IntPtr)(vars.MainMenuAddr + (i * 2) + 1), 0);
	}
	for (int i = 0; i < vars.Level_0.Length; i++)
	{
		memory.WriteValue<byte>((IntPtr)(vars.Level_0Addr + (i * 2)), (byte)vars.Level_0[i]);
		memory.WriteValue<byte>((IntPtr)(vars.Level_0Addr + (i * 2) + 1), 0);
	}	
	var scanner = new SignatureScanner(game, game.MainModule.BaseAddress, modules.First().ModuleMemorySize);


	version = "0.8.0+";

	print("[BET Autosplitter] DEBUG: BET Autosplitter loaded");

	// Match State hook -- Tells us the current state of the match
	IntPtr ptrmatchStateAddr = scanner.Scan(new SigScanTarget(0, // target the 0th bytes
	//48 8B 4C 24 20 48 8B 7C 24 ?? 48 8B ?? 24 50 48 85 C9 74 ?? E8 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 85 C9 74 ?? E8 ?? ?? ?? ?? 48 8B 54 24 ??
	"48 8B 4C 24 20", // mov rcx, qword ptr ss:[rsp+0x20]
	"48 8B 7C 24 ??", // mov rdi, qword ptr ss:[rsp+0x??]
	"48 8B ?? 24 50", // mov ??, qword ptr ss:[rsp+0x50]
	"48 85 C9 74 ?? E8 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 85 C9 74 ?? E8 ?? ?? ?? ?? 48 8B 54 24 ??"
	));
	
	if (ptrmatchStateAddr == IntPtr.Zero)
	{
		game.Resume();
		throw new Exception("Could not find matchState detour!");
	}

	// matchState == 0x0065006D00610047 GameStarted
	// matchState == 0x0065006A0062004F ObjectiveStarted
	// matchState == 0x007600610065004C LeavingMap
	// matchState == 0x0074006900610057 WaitingOnPlayers

	vars.matchState = game.AllocateMemory(80); // allocate 80 bytes for detour, first two bytes are for my variable
	memory.WriteValue<ulong>((IntPtr)vars.matchState, 0); // Set matchState to 0 which is the default "not loading" state
	vars.matchStateDetour = vars.matchState + 8; // skip over the first two bytes plus 16 to account for our map strings		
	vars.watchers.Add(new MemoryWatcher<ulong>(new DeepPointer((IntPtr)vars.matchState)){ Name = "matchState" });
	
	// Offset bytes
	byte byte1 = (byte)(memory.ReadValue<byte>((IntPtr)((ulong)ptrmatchStateAddr + 4)) + 0x10);
	byte byte2 = (byte)(memory.ReadValue<byte>((IntPtr)((ulong)ptrmatchStateAddr + 9)) + 0x10);
	byte byte3 = (byte)(memory.ReadValue<byte>((IntPtr)((ulong)ptrmatchStateAddr + 14)) + 0x10);
	
	// Register byte
	byte bytereg = (byte)(memory.ReadValue<byte>((IntPtr)((ulong)ptrmatchStateAddr + 12)));
	
	print("Current: " + byte1.ToString());
	print("Current: " + byte2.ToString());
	print("Current: " + byte3.ToString());
	var matchStateDetourBytes = new byte[]
	{
		// Check to see new match state
		0x50, // push rax
		0x48, 0x8b, 0x44, 0x24, 0x48, // movsxd rax, dword ptr ds:[rsp+0x30]
		0x48, 0x8b, 0x00, // mov rax, [rax]
		0x48, 0x89, 0x05, 0xE8, 0xFF, 0xFF, 0xFF,// mov [string1], rax
		// original instructions
		0x58, // pop rax
		// add 8 to original instructions since they reference RSP and we pushed to the stack
		0x48, 0x8B, 0x4C, 0x24, byte1, // mov rcx, qword ptr ss:[rsp+0x?? + 0x10]
		0x48, 0x8B, 0x7C, 0x24, byte2, // mov rdi, qword ptr ss:[rsp+0x?? + 0x10]
		0x48, 0x8B, bytereg, 0x24, byte3, // mov ??, qword ptr ss:[rsp+0x?? + 0x10]
		0xC3 // ret
	};
	
	// bytes to detour load start function
	var matchStateHookBytes = new List<byte>()
	{
		0x50,														// push rax
		0x48, 0xB8													// mov rax, jumploc
	};
	matchStateHookBytes.AddRange(BitConverter.GetBytes((ulong)vars.matchStateDetour));
	matchStateHookBytes.AddRange(new byte[] {
		0xFF, 0xD0,													// call rax			
		0x58,														// pop rax
		0x90
	});
	
	
	// isChangingLevel hook -- Tells if we are changing levels
	IntPtr ptrisChangingLevelAddr = scanner.Scan(new SigScanTarget(0, // target the 0th bytes
	//49 8d ?? C0 00 00 00 41 83 F1 01 48 8D 4C 24 40
	"49 8D ?? C0 00 00 00", // lea rdx, ds:[??+0xC0]
	"41 83 F1 01", // xor r9d, 0x01
	"48 8D 4C 24 40" // lea rcx, ss:[rsp+0x40]
	));
	
	if (ptrisChangingLevelAddr == IntPtr.Zero)
	{
		game.Resume();
		throw new Exception("Could not find isChangingLevel detour!");
	}

	// isChangingLevel == 1 means changing level
	// isChangingLevel == 0 means not changing level
	
	vars.isChangingLevel = game.AllocateMemory(80); // allocate 80 bytes for detour, first two bytes are for my variable
	memory.WriteValue<byte>((IntPtr)vars.isChangingLevel, 0); // Set isChangingLevel to 0 which is the default "not loading" state
	memory.WriteValue<ulong>((IntPtr)(vars.isChangingLevel + 2), (ulong)vars.MainMenuAddr); // Save address of the MainMenu path
	memory.WriteValue<ulong>((IntPtr)(vars.isChangingLevel + 10), (ulong)vars.Level_0Addr); // Save address of the MainMenu path
	vars.isChangingLevelDetour = vars.isChangingLevel + 2 + 8 + 8; // skip over the first two bytes plus 16 to account for our map strings	
	vars.watchers.Add(new MemoryWatcher<byte>(new DeepPointer((IntPtr)vars.isChangingLevel)){ Name = "isChangingLevel" });
	
	byte byte4 = (byte)(memory.ReadValue<byte>((IntPtr)((ulong)ptrisChangingLevelAddr + 2)));
	byte byte5 = 0;
	byte byte6 = 0;
	if (byte4 == 0x97)
	{
		// 0x97 means r15
		byte5 = 0xB7;
		byte6 = 0x8F;
	}
	else if (byte4 == 0x95)
	{
		// 0x95 means r13
		byte5 = 0xB5;
		byte6 = 0x8D;
	}
	
	byte byte7 = (byte)(memory.ReadValue<byte>((IntPtr)((ulong)ptrisChangingLevelAddr - 13)));
	byte byte8 = 0;
	byte byte9 = 0;
	byte byte10 = 0;
	byte byte11 = 0;
	if (byte7 == 0x06)
	{
		// 0x06 means r14
		byte8 = 0x4C;
		byte9 = 0xF7;
		byte10 = 0x49;
		byte11 = 0x3E;
	}
	else if (byte7 == 0x03)
	{
		// 0x03 means rbx
		byte8 = 0x48;
		byte9 = 0xDf;
		byte10 = 0x48;
		byte11 = 0x3f;
	}
	var isChangingLevelDetourBytes = new byte[]
	{
		// Check to see what map we are loading
		0x57, // push rdi
		0x56, // push rsi
		0x51, // push rcx
		0x52, // push rdx
		byte8, 0x89, byte9, // mov rdi, ??
		0x49, 0x8D, byte5, 0xE8, 0x00, 0x00, 0x00, // lea rsi, ds:[r15+0xE8] -- address of &unreal + 0x28 for current level
		0x49, 0x63, byte6, 0xF0, 0x00, 0x00, 0x00,// movsxd rcx, dword ptr ds:[r15+0xF0]
		0x80, 0xe9, 0x01, // sub cl, 1
		0x48, 0xD1, 0xE1, // shl rcx, 0x01
		byte10, 0x8B, byte11, // mov rdi, qword ptr ds:[??]
		0x48, 0x8B, 0x36, // mov rsi, qword ptr ds:[rsi]
		0xF3, 0xA6, // repe cmpsb
		0x74, 0x50, //je blah -- if the strings are the same then don't set variable
		// now check to see if we're going to the main menu
		0x48, 0x89, 0xDF, // mov rdi, rbx
		byte10, 0x8B, byte11, // mov rdi, qword ptr ds:[??]
		0xE8, 0x00, 0x00, 0x00, 0x00,// call 0
		0x5E, // pop rsi
		0x48, 0x83, 0xEE, 0x40, //sub rsi, 0x38
		0x48, 0x8B, 0x36, // mov rsi, qword ptr ds:[rsi]
		0x48, 0xC7, 0xC1, 0x44, 0x00, 0x00, 0x00, // mov rcx, 0x22
		0xF3, 0xA6, // repe cmpsb
		0x74, 0x32, //je blah -- if the strings are the same then don't set variable
		//0x66, 0xC7, 0x05, 0xAA, 0xFF, 0xFf, 0xFF, 0x01, 0x00,// mov [var], 1
		// now check to see if we're going to level_0
		0x48, 0x89, 0xDF, // mov rdi, rbx
		byte10, 0x8B, byte11, // mov rdi, qword ptr ds:[??]
		0xE8, 0x00, 0x00, 0x00, 0x00,// call 0
		0x5E, // pop rsi
		0x48, 0x83, 0xEE, 0x56, //sub rsi, 0x38
		0x48, 0x8B, 0x36, // mov rsi, qword ptr ds:[rsi]
		0x48, 0xC7, 0xC1, 0x4A, 0x00, 0x00, 0x00, // mov rcx, 0x22
		0xF3, 0xA6, // repe cmpsb
		0x75, 0x0B, //je blah -- if not level_0 then set var to 1. otherwise 2
		0x66, 0xC7, 0x05, 0x84, 0xFF, 0xFf, 0xFF, 0x02, 0x00,// mov [var], 2
		0xEB, 0x09, // jmp end
		0x66, 0xC7, 0x05, 0x79, 0xFF, 0xFf, 0xFF, 0x01, 0x00,// mov [var], 1
		// original instructions
		0x5A, // pop rax
		0x59, // pop rax
		0x5E, // pop rax
		0x5F, // pop rax
		// add 8 to original instructions since they reference RSP and we pushed to the stack
		0x49, 0x8D, byte4, 0xC0, 0x00, 0x00, 0x00, // lea rdx, ds:[r15+0xC0]
		0x41, 0x83, 0xF1, 0x01, // xor r9d, 0x01
		0x48, 0x8D, 0x4C, 0x24, 0x50, // lea rcx, ss:[rsp+0x40 + 0x10]
		0xC3 // ret
	};
	
	// bytes to detour load start function
	var isChangingLevelHookBytes = new List<byte>()
	{
		0x50,														// push rax
		0x48, 0xB8													// mov rax, jumploc
	};
	isChangingLevelHookBytes.AddRange(BitConverter.GetBytes((ulong)vars.isChangingLevelDetour));
	isChangingLevelHookBytes.AddRange(new byte[] {
		0xFF, 0xD0,													// call rax			
		0x58,														// pop rax
		0x90, 0x90
	});
	// suspend game while writing so it doesn't crash
	
	
	// Place hook on FLatentActionManager::AddNewAction	 
	IntPtr ptrIsExitingZoneAddr = scanner.Scan(new SigScanTarget(0, // target the 0th bytes
	//53 55
	"53",// push rbx
	"55", // push rbp
	"41 56", // push r14
	"48 83 EC 50", // sub rsp, 0x50
	"48 8B D9", // mov rbx, rcx
	"48 C7 44 24 78 00 00 00 00", // mov qword ptr ss:[rsp+0x78], 0x00
	"48 8D 4C 24 78" // lea rcx, ss:[rsp+0x78]
	));
	
	if (ptrIsExitingZoneAddr == IntPtr.Zero)
	{
		game.Resume();
		throw new Exception("Could not find ptrIsExitingZoneAddr detour!");
	}

	// isExitingZone == 2 means we already split but need to wait for level change
	// isExitingZone == 1 means exiting zone
	// isExitingZone == 0 means not exiting zone
	
	vars.isExitingZone = game.AllocateMemory(80); // allocate 80 bytes for detour, first two bytes are for variable
	memory.WriteValue<byte>((IntPtr)vars.isExitingZone, 0); // Set isExitingZone to 0 which is the default "not exiting" state
	memory.WriteValue<ulong>((IntPtr)vars.isExitingZone + 2, (ulong)vars.arrUUIDs); // Set isExitingZone to 0 which is the default "not exiting" state
	vars.isExitingZoneDetour = vars.isExitingZone + 2 + 8; // skip over the first 2 bytes plus 8 for our array address
	vars.watchers.Add(new MemoryWatcher<byte>(new DeepPointer((IntPtr)vars.isExitingZone)){ Name = "isExitingZone" });
	var isExitingZoneDetourBytes = new byte[]
	{
		0x53,//push rbx
		0x50,//push rax
//		0x41, 0x50, // push r8
		0x57, //push rdi
		0x48, 0x31, 0xc0,// xor rax, rax
		0x48, 0x8b, 0x1d, 0xEB, 0xFF, 0xFF, 0xFF,//mov rbx, array
//		0x4c, 0x8B, 0x44, 0x24, 0x38, // mov r8, qword ptr ss:[rsp+0x38]
		// loop
		0x48, 0x8b, 0x3c, 0x03,// mov rdi, [rbx + rax]
		0x48, 0x83, 0xff, 0x00,// cmp rdi, 0
		0x74, 0x14,// je end
		0x4c, 0x39, 0xc7,// cmp rdi, r8
		0x74, 0x06,//je set
		0x48, 0x83, 0xc0, 0x08,// add rax,8
		0xeb, 0xeb,//jmp loop
		0x66, 0xC7, 0x05, 0xCB, 0xFF, 0xFF, 0xFF, 0x01, 0x00,	// mov word ptr ds:[7FF78D6366BD],1 (set isExitingZone to 1)
		0x5F, // pop rdi
//		0x41, 0x58, //pop r8
		0x58, //pop rax
		0x5b, //pop rbx
		// original instructions
		0x48, 0x8B, 0xD9,// mov rbx, rcx
		0x48, 0xC7, 0x84, 0x24, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov qword ptr ss:[rsp+0x78 + 0x8 - 0x50 - 0x18], 0x00
		0x48, 0x8D, 0x8C, 0x24, 0x18, 0x00, 0x00, 0x00, // lea rcx, ss:[rsp+0x78 + 0x8 - 0x50 - 0x18]
		0xC3 // ret
	};
	
	// bytes to detour load start function
	var isExitingZoneHookBytes = new List<byte>()
	{
		//0x50,														// push rax
		0x48, 0xB8													// mov rax, jumploc
	};
	isExitingZoneHookBytes.AddRange(BitConverter.GetBytes((ulong)vars.isExitingZoneDetour));
	isExitingZoneHookBytes.AddRange(new byte[] {
		0xFF, 0xD0,													// call rax 
		0x53, 
		0x55,
		0x41, 0x56,
		0x48, 0x83, 0xEC, 0x50,
		0x90, 0x90, 0x90, 0x90, 0x90
	});
	
	try
	{
		// write the detour code at the allocated memory address
		game.WriteBytes((IntPtr)vars.matchStateDetour, matchStateDetourBytes);
		game.WriteBytes((IntPtr)vars.isChangingLevelDetour, isChangingLevelDetourBytes);
		game.WriteBytes((IntPtr)vars.isExitingZoneDetour, isExitingZoneDetourBytes);
		// write detour calls
		game.WriteBytes(ptrmatchStateAddr, matchStateHookBytes.ToArray());
		game.WriteBytes(ptrisChangingLevelAddr, isChangingLevelHookBytes.ToArray());
		game.WriteBytes(ptrIsExitingZoneAddr, isExitingZoneHookBytes.ToArray());
	}
	catch
	{
		vars.FreeMemory(game);
		game.Resume();
		throw;
	}
	finally
	{
		game.Resume();
	}	
}

update
{
	vars.watchers.UpdateAll(game);
}

start
{
	// matchState == 0x0065006D00610047 GameStarted
	// matchState == 0x0065006A0062004F ObjectiveStarted
	// matchState == 0x007600610065004C LeavingMap
	// matchState == 0x0074006900610057 WaitingOnPlayers
	var doStart = (vars.watchers["matchState"].Current > 0x0 && vars.watchers["matchState"].Old == 0x0) || vars.watchers["isChangingLevel"].Current == 2;
	//var waitingOrStarted = (vars.watchers["matchState"].Current == 0x0074006900610057) || (vars.watchers["matchState"].Current == 0x0065006A0062004F) || (vars.watchers["matchState"].Current == 0x0065006D00610047);
	//var loadingMap2 = (waitingOrStarted && vars.watchers["matchState"].Old == 0x0);
	
	//if (loadingMap2)
	//{
		//print("loadaidj")
	//}
	
	// print("Current: " + vars.watchers["matchState"].Current.ToString());
	// print("Old: " + vars.watchers["matchState"].Old.ToString());
	if (doStart)
	{
		if(vars.watchers["isChangingLevel"].Current == 2)
		{
			print("blah!!!");
			// We are loading level_0
			
			if (vars.watchers["matchState"].Current == 0x0065006D00610047 || vars.watchers["matchState"].Current == 0x0065006A0062004F) //GameStarted
			{
				memory.WriteValue<ulong>((IntPtr)vars.matchState, 0); // Set matchState to 0
				memory.WriteValue<byte>((IntPtr)vars.isChangingLevel, 0); // Set isChangingLevel to 0
				vars.watchers["matchState"].Current = 0x0;
				vars.watchers["matchState"].Old = 0x0;
				vars.watchers["isChangingLevel"].Current = 0;
				return true;
			}
			
			return false;
		}
		else if (vars.watchers["isChangingLevel"].Current == 1)
		{
			memory.WriteValue<ulong>((IntPtr)vars.matchState, 0); // Set matchState to 0
			memory.WriteValue<byte>((IntPtr)vars.isChangingLevel, 0); // Set isChangingLevel to 0
			vars.watchers["matchState"].Current = 0x0;
			vars.watchers["matchState"].Old = 0x0;
			vars.watchers["isChangingLevel"].Current = 0;
			return true;
		}
		else
		{
			print("blah!!!1");
			if(vars.watchers["matchState"].Current == 0x007600610065004C)
			{
				print("blah!!!2");
				// If state is LeavingMap then ignore it and set it back to 0
				memory.WriteValue<ulong>((IntPtr)vars.matchState, 0); // Set matchState to 0
				vars.watchers["matchState"].Current = 0x0;
				vars.watchers["matchState"].Old = 0x0;
				return false;
			}
			//if(vars.watchers["matchState"].Current == 0x0065006A0062004F && vars.watchers["matchState"].Old == 0x0)
			//{
			//	print("blah!!!3");
			//	memory.WriteValue<ulong>((IntPtr)vars.matchState, 0); // Set matchState to 0
			//	vars.watchers["matchState"].Current = 0x0;
			//	vars.watchers["matchState"].Old = 0x0;
			//	return false;
			//}
			if(vars.watchers["matchState"].Current == 0x0074006900610057 && vars.watchers["matchState"].Old == 0x0)
			{
				memory.WriteValue<ulong>((IntPtr)vars.matchState, 0); // Set matchState to 0
				vars.watchers["matchState"].Current = 0x0;
				vars.watchers["matchState"].Old = 0x0;
				return false;
			}
			print("blah!!!4");
			memory.WriteValue<ulong>((IntPtr)vars.matchState, 0); // Set matchState to 0
			memory.WriteValue<byte>((IntPtr)vars.isChangingLevel, 0); // Set isChangingLevel to 0
			vars.watchers["matchState"].Current = 0x0;
			vars.watchers["matchState"].Old = 0x0;
			vars.watchers["isChangingLevel"].Current = 0;
			return true;
		}
		
	}

	return false;
}

split
{
	if (vars.watchers["isChangingLevel"].Current == 1)
	{
		vars.watchers["isChangingLevel"].Current = 0;
		memory.WriteValue<byte>((IntPtr)vars.isChangingLevel, 0); // Set isChangingLevel to 0
		if (vars.watchers["isExitingZone"].Current == 0x02)
		{
			vars.watchers["isExitingZone"].Current = 0x00;
			memory.WriteValue<byte>((IntPtr)vars.isExitingZone, 0); // Set isExitingZone to 0
			return false;
		}
		return true;
	}
	if (vars.watchers["isExitingZone"].Current == 0x01)
	{
		vars.watchers["isExitingZone"].Current = 0x02;
		memory.WriteValue<byte>((IntPtr)vars.isExitingZone, 2); // Set isExitingZone to 2
		return true;
	}

	return false;
}

isLoading
{	
	if (vars.watchers["matchState"].Current == 0x007600610065004C)
	{
		return true;
	}
	return false;
}

shutdown 
{
}

onReset
{
	try
	{
		memory.WriteValue<ulong>((IntPtr)vars.matchState, 0); // Set matchState to 0
		memory.WriteValue<byte>((IntPtr)vars.isChangingLevel, 0);
		memory.WriteValue<byte>((IntPtr)vars.isExitingZone, 0);
		vars.watchers["matchState"].Current = 0x0;
	}
	catch
	{
	}
}
