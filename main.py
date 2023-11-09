import multiprocessing
import threading
from turtle import rt
from scapy.layers.inet import IP, UDP, TCP
from scapy.all import *
from scapy.utils import wrpcap
import ctypes
import tkinter.messagebox
from tkinter import ttk
import tkinter as tk
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import psutil


def onAnalyze():
    rt = pd.read_csv("D:/SLIIT/Research/Research/CICFlowMeter-4.0/bin/data/daily/2023-05-17_Flow.csv")
    X_rt = rt[['Fwd Pkt Len Mean','Fwd Seg Size Avg','Pkt Len Min','Fwd Pkt Len Min','Pkt Len Mean','Protocol','Fwd Act Data Pkts','Pkt Size Avg','Tot Fwd Pkts','Subflow Fwd Pkts']] 

    X_rt.rename(columns={'Fwd Pkt Len Mean': 'Fwd Packet Length Mean',
                     'Fwd Seg Size Avg': 'Avg Fwd Segment Size',
                     'Pkt Len Min': 'Min Packet Length',
                     'Fwd Pkt Len Min': 'Fwd Packet Length Min',
                     'Pkt Len Mean': 'Packet Length Mean',
                     'Protocol': 'Protocol',
                     'Fwd Act Data Pkts': 'act_data_pkt_fwd',
                     'Pkt Size Avg': 'Average Packet Size',
                     'Tot Fwd Pkts': 'Total Fwd Packets',
                     'Subflow Fwd Pkts': 'Subflow Fwd Packets'})


def trainingThread():
    df = pd.read_csv("D:/SLIIT/Research/Research/Dataset/TrainingDay.csv")
    df = df[['Fwd Packet Length Mean','Avg Fwd Segment Size','Min Packet Length','Fwd Packet Length Min','Packet Length Mean','Protocol','act_data_pkt_fwd','Average Packet Size','Total Fwd Packets','Subflow Fwd Packets', 'Label']]
    df.loc[df['Label'] == 'BENIGN', 'Label'] = 0
    df.loc[df['Label'] == 'DrDoS_DNS', 'Label'] = 1
    df['Label'] = df['Label'].astype(int)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace = True)
    df = df[(df >= 0).all(axis=1)]
    Y = df["Label"].values
    X = df[['Fwd Packet Length Mean','Avg Fwd Segment Size','Min Packet Length','Fwd Packet Length Min','Packet Length Mean','Protocol','act_data_pkt_fwd','Average Packet Size','Total Fwd Packets','Subflow Fwd Packets']]

    global model
    model = RandomForestClassifier(n_estimators = 20, random_state = 42)
    model.fit(X, Y)
    
    label.configure(text = "Done        ")
    Button_0["state"] = "normal"


def onTraining():
    Button_0["state"] = "disabled"
    label.configure(text = 'Training...')
    startThread(trainingThread)


def handelPacket(p):
    #p.show()
    addTreeData = []
    addTreeData.append(p[IP].src)
    addTreeData.append(p[IP].dst)
    if p[IP].proto == 6:
        addTreeData.append('TCP')
        addTreeData.append(p[TCP].sport)
        addTreeData.append(p[TCP].dport)

    elif p[IP].proto == 17:
        addTreeData.append('UDP')
        addTreeData.append(p[UDP].sport)
        addTreeData.append(p[UDP].dport)

    index = treeview.insert('', 'end', values=addTreeData)
    treeview.see(index)
    root.update()
    wrpcap('traffic.pcap', p, append=True)



def getPack():
    sniff(filter="(tcp or udp) and ip and !multicast", count=0, prn=handelPacket)
    


def startThread(func, *args):
    global t
    t = threading.Thread(target=func, daemon=True)
    t.start()


def _async_raise(tid, exctype):
   
    tid = ctypes.c_long(tid)
    if not inspect.isclass(exctype):
        exctype = type(exctype)
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, ctypes.py_object(exctype))
    if res == 0:
        raise ValueError("invalid thread id")
    elif res != 1:
     
        ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, None)
        raise SystemError("PyThreadState_SetAsyncExc failed")


def stopThread():
    _async_raise(t.ident, SystemExit)


b1_state = 0
def onStart():
    global b1_state
    if (b1_state % 2) == 0:
        startThread(getPack)
        Button_1['text'] = 'Stop'

    else:
        stopThread()
        global processlist
        processlist = []
        for proc in psutil.process_iter():
            processlist.append(psutil.Process(proc.pid))
        global connections
        connections = psutil.net_connections(kind="inet4")
        Button_1['text'] = 'Start'    

    b1_state += 1

if __name__ == '__main__':

    multiprocessing.freeze_support()
    root = tk.Tk()
    root.resizable(False, False)
    root.title("Network monitoring tool")
    root.geometry('780x720')

    ctypes.windll.shcore.SetProcessDpiAwareness(1)
    ScaleFactor = ctypes.windll.shcore.GetScaleFactorForDevice(0)
    root.tk.call('tk', 'scaling', ScaleFactor / 75)

    Button_0 = tk.Button(root, text='Training', width=10, height=1, command=onTraining)
    Button_0.grid(row=0, column=0, padx=10, pady=10)
    
    Button_1 = tk.Button(root, text='Start', width=10, height=1, command=onStart)
    Button_1.grid(row=0, column=1, padx=10, pady=10)

    Button_2 = tk.Button(root, text='Analyze', width=10, height=1, command=onAnalyze)
    Button_2.grid(row=0, column=2, padx=10, pady=10)
    
    treeview = ttk.Treeview(root, height=30)
    treeview['show'] = 'headings'
    treeview['column'] = ('Source IP', 'Destination IP', 'Protocol', 'SPort', 'DPort')
    for column in treeview['column']:
        treeview.column(column, width=150)
        treeview.heading(column, text=column)

    treeview.grid(row=1, column=0, columnspan=6, sticky='NSEW')

    vbar = ttk.Scrollbar(root, orient='vertical', command=treeview.yview)
    treeview.configure(yscrollcommand=vbar.set)
    vbar.grid(row=1, column=7, sticky='NS')

    label = tk.Label(root, text = "            ")
    label.grid(row=2, column=0, sticky='NW')

    root.mainloop()
