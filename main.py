from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import datetime
import hashlib
import json
import threading
import time
import sqlite3
import os
import sys

# Add the 'add-ons' subdirectory to sys.path to import db_manager
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'add-ons'))

from db_manager import VoterDatabase  # Import the VoterDatabase class from db_manager.py

# Create the Flask application
app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a secret key for session management

# Initialize the database
voter_db = VoterDatabase()

# Function to authenticate a user
def authenticate_user(npi, password):
    try:
        connection = sqlite3.connect(voter_db.database_file)  # Connect to the SQLite database
        cursor = connection.cursor()
        cursor.execute("SELECT npi, full_name, password, role FROM voters WHERE npi = ?", (npi,))
        user = cursor.fetchone()  # Retrieve the user corresponding to the NPI
        connection.close()
        if user:
            decrypted_password = voter_db.decrypt(user[2])  # Decrypt the password
            if decrypted_password == password:
                decrypted_full_name = voter_db.decrypt(user[1])  # Decrypt the full name
                decrypted_role = voter_db.decrypt(user[3])  # Decrypt the role
                return {'npi': user[0], 'full_name': decrypted_full_name, 'role': decrypted_role}  # Return user details as a dictionary
        return None
    except sqlite3.Error as error:
        print("Error while connecting to SQLite database:", error)
        return None

# Class representing a block in the blockchain
class Block:
    def __init__(self, index, timestamp, npi, data, previous_hash):
        self.index = index  # Index of the block in the chain
        self.timestamp = timestamp  # Timestamp of block creation
        self.npi = npi  # NPI of the user
        self.data = data  # Voting data
        self.previous_hash = previous_hash  # Hash of the previous block
        self.proof = 0  # Initialize proof to 0
        self.hash = self.calculate_hash()  # Calculate the hash of the block
        self.hash_attempts = 0  # Counter for hash attempts
        self.hash_rate = 0  # Store the hash rate

    def calculate_hash(self):
        hash_string = (
            str(self.index)
            + str(self.timestamp)
            + str(self.npi)
            + str(self.data)
            + str(self.previous_hash)
            + str(self.proof)  # Include proof in the hash calculation
        )
        return hashlib.sha256(hash_string.encode()).hexdigest()  # Return the calculated hash

    def mine_block(self, difficulty):
        start_time = time.time()  # Record the start time
        while self.hash[:difficulty] != "0" * difficulty:
            self.proof += 1
            self.hash = self.calculate_hash()
            self.hash_attempts += 1  # Increment hash attempts

        end_time = time.time()  # Record the end time
        duration = end_time - start_time  # Calculate the duration
        self.hash_rate = self.hash_attempts / duration  # Calculate the hash rate
        print(f"Block mined in {duration:.2f} seconds with hash rate: {self.hash_rate:.2f} hashes/second")
        return self.hash_rate

    def __str__(self):
        return json.dumps({
            "index": self.index,
            "timestamp": self.timestamp.isoformat(),  # Convert timestamp to ISO format
            "npi": self.npi,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "proof": self.proof,
            "hash": self.hash,
            "hash_attempts": self.hash_attempts,  # Include hash attempts in the string representation
            "hash_rate": self.hash_rate  # Include hash rate in the string representation
        }, indent=4)


# Class representing the blockchain
class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]  # Initialize the chain with the genesis block
        self.difficulty = 4  # Adjust difficulty as needed
        self.voters = set()  # Set to store voter NPIs
        self.vote_closed = False  # Indicator for whether the vote is closed

    def create_genesis_block(self):
        return Block(0, datetime.datetime.now(), "", "Genesis Block", "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, new_block):
        new_block.previous_hash = self.get_latest_block().hash
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)
        print("New block added to the blockchain:", new_block)

    def is_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.hash != current_block.calculate_hash():
                return False

            if current_block.previous_hash != previous_block.hash:
                return False

        return True

    def record_vote(self, full_name, npi, choice):
        if self.vote_closed:
            return "The vote is closed!"

        if npi in self.voters:
            return "Your vote has already been recorded!"

        if choice not in ["Paul", "Pierre"]:
            return "Invalid choice!"

        self.voters.add(npi)
        block = Block(len(self.chain), datetime.datetime.now(), npi, f"Voter: {full_name}, Voted for: {choice}", "")
        self.add_block(block)
        return block.hash  # Return the vote hash

    def get_block_by_hash(self, hash_value):
        for block in self.chain:
            if block.hash == hash_value:
                return block
        return None

    def get_winner(self):
        candidate_votes = {"Paul": 0, "Pierre": 0}
        for block in self.chain[1:]:
            if "Paul" in block.data:
                candidate_votes["Paul"] += 1
            elif "Pierre" in block.data:
                candidate_votes["Pierre"] += 1

        if candidate_votes["Paul"] == candidate_votes["Pierre"]:
            return "No one because of a tie"
        else:
            return max(candidate_votes, key=candidate_votes.get)

    def get_average_hash_rate(self):
        total_hash_rate = sum(block.hash_rate for block in self.chain[1:])
        num_blocks = len(self.chain) - 1  # Exclude the genesis block
        return total_hash_rate / num_blocks if num_blocks > 0 else 0


# Initialize the blockchain
blockchain = Blockchain()

# Function to close the vote after a specified duration
def close_vote():
    global blockchain, start_time, vote_duration
    vote_duration = 300  # 5 minutes
    start_time = time.time()
    print("The votes will close in", vote_duration, "seconds")
    time.sleep(vote_duration)
    blockchain.vote_closed = True
    print("Votes Closed!")

# Start the timer to close the vote
timer_thread = threading.Thread(target=close_vote)
timer_thread.start()

# Function to calculate the remaining time
def time_remaining():
    global vote_duration, start_time
    remaining_time = max(vote_duration - int(time.time() - start_time), 0)

    days = remaining_time // (24 * 3600)
    remaining_time = remaining_time % (24 * 3600)
    hours = remaining_time // 3600
    remaining_time %= 3600
    minutes = remaining_time // 60
    remaining_time %= 60
    seconds = remaining_time

    return {'days': days, 'hours': hours, 'minutes': minutes, 'seconds': seconds}

# Function to filter data based on time
def filter_data_based_on_time(hours):
    filtered_data = []
    cutoff_time = datetime.datetime.now() - datetime.timedelta(hours=hours)
    for block in blockchain.chain:
        if block.timestamp >= cutoff_time:
            filtered_data.append(block)
    return filtered_data

# Route to vote
@app.route("/vote", methods=["GET", "POST"])
def vote():
    if not session.get('authenticated', False):  # Check if the user is authenticated
        return redirect(url_for('login'))

    if session.get('authenticated_role', '').lower() == 'admin':  # Ensure only voters can access the vote page
        return redirect(url_for('display_results'))

    if request.method == "POST":
        full_name = session.get('authenticated_full_name', None)
        npi = session.get('authenticated_npi', None)
        choice = request.form["choice"]
        if blockchain.vote_closed:
            return render_template("Vote/vote.html", message="The vote is closed!")
        hash_value = blockchain.record_vote(full_name, npi, choice)
        if hash_value == "Your vote has already been recorded!":
            return render_template("Vote/vote.html", message=hash_value)
        else:
            return render_template("vote_success/vote_success.html", hash_value=hash_value, end_time=(datetime.datetime.now() + datetime.timedelta(seconds=180)))
    return render_template("Vote/vote.html", active_page="vote")

# Route for the home page
@app.route("/", methods=["GET", "POST"])
def home():
    return render_template("Home/home.html", active_page="home")

# Route to log out
@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()  # Clear the session data
    return redirect(url_for("home"))

# Route for the login page
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        npi = request.form["npi"]
        password = request.form["password"]
        user = authenticate_user(npi, password)
        if user:
            session['authenticated'] = True  # Set session to authenticated
            session['authenticated_npi'] = user['npi']
            session['authenticated_full_name'] = user['full_name']
            session['authenticated_role'] = user['role']
            return redirect(url_for('display_results' if user['role'].lower() == 'admin' else 'vote'))
        else:
            return render_template("Login/login.html", error_message="Invalid NPI or password")
    return render_template("Login/login.html", active_page="login")

# Route to display voting results
@app.route("/results", methods=["GET"])
def display_results():
    if not session.get('authenticated', False):  # Check if the user is authenticated
        return redirect(url_for('login'))

    if session.get('authenticated_role', '').lower() != 'admin':  # Ensure only admins can access the results page
        return redirect(url_for('home'))

    winner = blockchain.get_winner()
    return render_template("Results/results.html", winner=winner, total_voters=len(blockchain.voters), is_vote_closed=blockchain.vote_closed, hash_rate=blockchain.get_average_hash_rate())

# Route to get time remaining
@app.route("/time_remaining", methods=["GET"])
def get_time_remaining():
    return jsonify(time_remaining())  # Return the remaining time as a JSON response

# Route to display all blocks
@app.route("/blocks", methods=["GET"])
def display_blocks():
    blocks = [json.loads(str(block)) for block in blockchain.chain]  # Convert blocks to JSON
    return jsonify(blocks)

# Route to get blocks from the last x hours
@app.route("/blocks/<int:hours>", methods=["GET"])
def get_blocks(hours):
    filtered_blocks = filter_data_based_on_time(hours)
    blocks = [json.loads(str(block)) for block in filtered_blocks]
    return jsonify(blocks)

# Route to display a block by its hash
@app.route("/block/<string:hash_value>", methods=["GET"])
def display_block_by_hash(hash_value):
    block = blockchain.get_block_by_hash(hash_value)
    if block:
        return jsonify(json.loads(str(block)))
    return jsonify({"message": "Block not found"})

# Run the application
if __name__ == "__main__":
    app.run(debug=True)
