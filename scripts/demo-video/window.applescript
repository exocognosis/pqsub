-- Open the demo window with the pqc-demo profile and report "windowId<TAB>tty".
-- usage: osascript window.applescript DEMO_SH STAGE TAKE X1 Y1 X2 Y2
on run argv
	set demoSh to item 1 of argv
	set stageDir to item 2 of argv
	set takeDir to item 3 of argv
	set b to {(item 4 of argv) as integer, (item 5 of argv) as integer, (item 6 of argv) as integer, (item 7 of argv) as integer}
	tell application "Terminal"
		set t to do script "exec /bin/bash --noprofile --norc " & quoted form of demoSh & " " & quoted form of stageDir & " " & quoted form of takeDir
		set current settings of t to settings set "pqc-demo"
		set theTty to tty of t
		set wid to missing value
		repeat with w in windows
			repeat with tb in tabs of w
				if tty of tb is theTty then set wid to id of w
			end repeat
		end repeat
		if wid is missing value then error "demo window not found"
		activate
		delay 1
		set bounds of window id wid to b
		set index of window id wid to 1
		return (wid as text) & (character id 9) & theTty
	end tell
end run
