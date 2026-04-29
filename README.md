# NeuralGuard
AI NETWROK THREAT DETECTION SYSTEM
🛡️ NeuralGuard: The AI-Powered Shield for Your Digital Home
Defending the "Trust Gap" with Advanced Machine Learning
In an era where our lives are lived online, the security of our home and business networks has never been more critical. Yet, the very foundation of how our devices talk to each other is based on a 40-year-old "trust" system that is easily broken by hackers. NeuralGuard is a revolutionary Python-based prototype that uses Artificial Intelligence to identify, flag, and stop these invisible intruders.

📖 Part 1: The Story of the Invisible Thief (For Everyone)
To understand why you need NeuralGuard, we have to look at a secret conversation happening in your house every second.

The Identity Game: IP vs. MAC
Imagine your home network is a busy apartment complex.

The IP Address (The Room Number): This tells the internet where to send your data. It’s like saying, "Send this package to Room 305."

The MAC Address (The Fingerprint): This is the actual person living in the room. This "fingerprint" is burned into your phone or laptop when it is made; it never changes.

The Problem: The "Fake Mailman" Trick (ARP Spoofing)
There is a rule on the internet called ARP. It is very trusting. It’s like a mailman walking into the hallway and shouting, "Who lives in Room 305?"

Usually, your computer shouts back, "That’s me!" and takes the mail. But a hacker can play a trick:

The Double Lie: The hacker tells your computer, "I am the Mailman!" and simultaneously tells the real Mailman, "I am the person in Room 305!"

The Interception: Now, the mailman gives your private letters (passwords, photos, bank details) to the hacker. The hacker reads them, copies them, and then hands them to you so you never suspect a thing.

This is called a Man-in-the-Middle (MitM) attack. It is silent, invisible, and happens inside your house, where most security systems aren't even looking.

🧠 Part 2: How the AI "Brain" Works (Deep Dive)
Most security systems are like a "Most Wanted" poster—if a hacker isn't on the list, they get through. NeuralGuard is different. It doesn't look for people; it looks for behavior.

1. Learning the "Heartbeat"
When you first turn on NeuralGuard, it enters a Learning Phase. It watches the normal rhythm of your network. It memorizes which "Fingerprints" (MAC) belong to which "Rooms" (IP). It builds a mathematical map of what a "Safe Day" looks like.

2. Anomaly Detection
Our AI uses a Neural Network (a Multi-Layer Perceptron). This is a digital brain that analyzes thousands of packets per second. It looks for three "Red Flags":

Identity Conflicts: If two different fingerprints claim to be the same room at the same time.

Shouting Frequency: Hackers have to send "fake" messages constantly to keep their trick working. The AI detects this "rapid-fire" shouting.

Pattern Shifts: The AI assigns a "Danger Score" (from 0 to 1). If the score jumps above a certain level, it knows a human couldn't possibly be making those requests—it must be a hacking tool like Bettercap or Ettercap.

💰 Part 3: Why NeuralGuard? (The Value Proposition)
You might ask: "Why not just buy a fancy $500 security router?"

A. Professional Hardware is "Static"
Traditional hardware uses fixed rules. If a hacker finds a new way to lie, the hardware won't notice until the manufacturer sends an update months later. NeuralGuard is Dynamic—it evolves and learns the specific quirks of your devices.

B. The Internal Blindspot
Most routers act as a "Front Gate" to the internet. They look for hackers coming from China or Russia. But ARP attacks come from Inside the house (like a guest or a compromised smart-bulb). NeuralGuard acts as an internal security guard walking the hallways inside the building.

C. Zero Cost, High Performance
By using Python and Open Source logic, NeuralGuard provides elite-level security for individuals, small businesses, and schools without the need for expensive subscriptions or hardware.

🛠️ Part 4: Technical Manual & Setup Guide
NeuralGuard is designed to be powerful on the inside, but simple on the outside. Follow these steps to secure your perimeter.

Phase 1: The Toolkit
The Files: Ensure arp_detector.py and index.html are in the same folder.

The "Eyes" (Npcap): Python needs special "eyes" to see raw network traffic. Download and install Npcap from nmap.org/npcap/.

Important: During installation, you must check the box: "Install Npcap in WinPcap API-compatible Mode".

Your IP Address: Open your Terminal (or Command Prompt), type ipconfig, and find your IPv4 Address (it usually looks like 192.168.X.X).

Phase 2: Deploying the Sentry
Open Terminal: Navigate to the folder where you saved the files.

Run the Program: Execute the command:

Bash
python arp_detector.py
