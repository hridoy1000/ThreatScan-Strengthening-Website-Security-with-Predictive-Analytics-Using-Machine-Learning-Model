import pyshark

capture=pyshark.LiveCapture(display_filter='ip.addr == 192.168.0.197')
capture.set_debug()
capture.sniff(timeout=1)
for p in capture:
    print(p)
capture.close()    
print("done")