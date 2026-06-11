Set wsc = CreateObject("WScript.Shell")

Do

WScript.Sleep (60*1000)

wsc.SendKeys ("{SCROLLLOCK 2}")

Loop