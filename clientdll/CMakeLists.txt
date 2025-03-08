add_library(HookToolClientDLL SHARED
	"dllmain.cpp"
	"hooks.cpp"
)

target_link_libraries(HookToolClientDLL PRIVATE 
	minhook
	Shlwapi.lib
)