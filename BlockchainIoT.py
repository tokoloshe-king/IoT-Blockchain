import socket
import websockets
import random
import pickle
from hashlib import sha256
import time
import datetime
import json
import asyncio
import traceback
import string 
import pickle
import sys
from asyncio import exceptions
from os import urandom
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

from concurrent.futures import TimeoutError


class Block:
    """
    Constructor for the `Block` class.
    :param index:         Unique ID of the block.
    :param data:          data contained in block
    :param lastHash: Hash of the previous block in the chain which this block is part of.   

    block needs method to calculate Hash of current data                                     
    """
    def __init__(self, index,timestamp, data, last_hash,nonce=0 ):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.last_hash = last_hash
        self.nonce = nonce


    def calculate_hash(self):
        """
        Method to calculate Hash of block
        """

        block_data = pickle.dumps(self.__dict__)
        return sha256(block_data).hexdigest()

    @property
    def get_values(self):
        return (self.index,self.timestamp,self.data,self.last_hash)


class BlockChain:
    """
    Constructor for Blockchain class
    Takes no initial parameters 
    chain is an array of blocks
    """

    difficulty = 4

    def __init__(self):
        self.unconfirmed_transactions = []
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        """
        A function to generate genesis block and appends it to
        the chain. The block has index 0, previous_hash as 0, and
        a valid hash.
        """
        genesis_block = Block(0,'0', ["Genesis"], '0')
        genesis_block.signature = 'evan is satoshi nakamoto'
        genesis_block.hash = BlockChain.proof_of_work(genesis_block)
        self.chain.append(genesis_block)

    @property
    def last_block(self):
        """
        @property is a getter, retrieves last_block
        """
        return self.chain[-1]

    def print_chain(self):
        for blocks in self.chain:
            print(vars(blocks))

    @staticmethod
    def proof_of_work(block):
        """
        function that calculates hash using different nonce values to
        meet blockchain difficulty
        """
        block.nonce = 1

        computed_hash = block.calculate_hash()
        while not computed_hash.startswith('0'* BlockChain.difficulty):
            block.nonce += 1
            computed_hash = block.calculate_hash()

        return computed_hash

    def add_block(self, block, proof):
        """
        function to add block to the chain
        """
        previous_hash = self.last_block.hash

        if previous_hash != block.last_hash:
            print("last hashes do not match")
            return False

        if not BlockChain.is_valid_proof(block,proof):
            print("block hash is not valid")
            return False

        block.hash = proof
        self.chain.append(block)
        return True

    @classmethod
    def is_valid_proof(cls,block, block_hash):
        """
        check if block_hash is valid hash of block and satisfies
        the difficulty criteria
        """
        try:
            block.hash
        except AttributeError:
            None

        else:
            delattr(block, 'hash')

        return (block_hash.startswith('0'*BlockChain.difficulty) and 
                block_hash == block.calculate_hash())

    def add_new_transaction(self, transaction):
        self.unconfirmed_transactions.append(transaction)

    def mine_block(self, signature):
        """
        function that adds pending transactions to blockchain, putting them into
        block and finding proof of work
        """
        if not self.unconfirmed_transactions:
            return False

        last_block = self.last_block

        new_block = Block(index=last_block.index + 1,timestamp = time.time(),
                          data=self.unconfirmed_transactions[0],
                          last_hash=last_block.hash)

        new_block.signature = signature
        proof = self.proof_of_work(new_block)
        self.add_block(new_block, proof)
        self.unconfirmed_transactions.pop(0)
        return new_block.index       


    @classmethod
    def validate_chain(cls, chain):
        """
        validate incoming chain and compare to internal chain,
        if it is longer and all blocks are valid
        then update internal chain.
        """
        result = True
        previous_hash = '0'

        # Iterate through every block
        for block in chain:
            block_hash = block.hash
            # remove the hash field to recompute the hash again
            # using `compute_hash` method.           
            delattr(block, "hash")           

            if not cls.is_valid_proof(block, block_hash) or \
                    previous_hash != block.last_hash:
                    
                result = "False"+ str(block.index)
                break

            block.hash, previous_hash = block_hash, block_hash

        return result
'''
Following block of code is the setup of the node, initialises the Blockchain and ports,
generates the RSA public and private keys
'''
private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048, backend=default_backend())
public_key = private_key.public_key()
pem_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
 )

SIGNATURE = None

IP_ADDRESS = '192.168.0.160'



try:
    NAME = sys.argv[1] 
    PORT = sys.argv[2]
except IndexError:
    NAME = socket.gethostname()
    PORT = 5005

schedule = [0]*24
host = NAME 
Local_Power = 15
WALLET = {'Total_Power' : 0, host : schedule}
blockchain = BlockChain()
CONNECTIONS = set()
SERVER_CONNECTIONS = set()
LISTENER_TASK = None



class ConnectionHandler:
    '''
    The superclass for the nodes, contain both server and client code,
    enable p2p communication as all nodes are identical
    '''
    websocket = None
    hostname = None
    uri = None
    state = 'Disconnect'
    public_key = None

    async def send(self, message):
        '''
        generic send func
        '''
        try:
            data = pickle.dumps(message)
            await self.websocket.send(data)
        except:
            traceback.print_exc()

    async def recv(self):
        try:
            message = await self.websocket.recv()
            data = pickle.loads(message)
            #print(f'type: {type(data)}')
            return data
        except:
            traceback.print_exc()

    async def login(self):
        try:
            self.websocket = await asyncio.wait_for(websockets.connect(self.uri),timeout=2)
        except TimeoutError:
            print(f'connection timed out to{self.uri}')
            return
        except ConnectionRefusedError:
            print(f'connection refused to{self.uri}')
            return   
        except:
            return

        print(f'sending name: {NAME}')
        await self.send({'hostname': NAME,'public_key': pem_public_key})

        reply = await self.recv()
        self.hostname = reply['hostname']
        self.public_key = serialization.load_pem_public_key(reply['public_key'],backend=default_backend())

        schedule = [0]*24
        Name = self.hostname 
        new_dict = {Name : schedule}
        WALLET.update(new_dict)
        #print(WALLET)

        confirmation = await self.recv()
        confirmed = confirmation['Connection']
        if confirmed == 'authorised':
            self.state = 'Connected'
            print(f'New connection from {self.hostname}')
            return



    async def welcome(self) -> bool:
        '''
        function handles the greeting with a new connection, checks incoming message to see if it includes the hostname,
        if so it sends back a crypto challenge for the connecting node, after the node sends it's password, current node
        checks is password is valid then enables connection to node, and changes status to connected
        '''
        global WALLET
        global Total_Power 
        greeting = await self.recv()
        #print(f'{greeting}')

        if 'hostname' not in greeting:
            await self.send({'Connection':'unauthorised'})
            return False
        if len(greeting['hostname']) > 1024:
            await self.send({'Connection': 'unauthorised'})
            return False


        self.hostname = greeting['hostname']
        #print(greeting['public_key'])
        self.public_key = serialization.load_pem_public_key(greeting['public_key'],backend=default_backend())
        await self.send({'hostname': NAME,'public_key': pem_public_key})

        schedule = [0]*24
        Name = self.hostname
        new_dict = {Name : schedule}
        WALLET.update(new_dict)
        #print(WALLET)

        await self.send({'Connection': 'authorised'})
        self.state = 'Connected'
        asyncio.get_event_loop().create_task(self.listener())
        #asyncio is an asynchronous task that will run the listener so that the node can always accept a new connection
        return True



    async def listener(self):
        '''
        function that listens for messages on the websocket port from a connection, this will be run asynchronously in a loop while 
        there is a connection
        '''
        global blockchain
        global WALLET
        try:
            async for message in self.websocket:
                data = pickle.loads(message)
                print(data)
                print(time.time())
                op_type = data['op_type']

                if op_type == 'new_block':
                    '''
                    new block is sent, must send back ack if valid block
                    '''                   
                    new_block = data['data']
                    tx = pickle.dumps(new_block.data)
                    #print(tx)
                    sign = new_block.signature
                    #print(sign)
                    try:
                        self.public_key.verify( sign,
                                            tx ,
                                            padding.PSS(
                                                mgf=padding.MGF1(hashes.SHA256()),
                                                salt_length=padding.PSS.MAX_LENGTH),
                                            hashes.SHA256())
                        print('valid signature')
                    except InvalidSignature:
                        pass
                    

                    if data['chain_length'] > len(blockchain.chain):
                        proof = new_block.hash
                        if not blockchain.add_block(new_block,proof):
                            print(f'Block {new_block.index} is not valid from {self.hostname}')
                            await self.send({'op_type': 'response',  'status':'invalid'})
                        else: 
                            temp_wallet = new_block.data
                            WALLET[self.hostname] = temp_wallet[self.hostname]
                            WALLET['Total_Power'] = temp_wallet['Total_Power'] 
                            print(f'Block {new_block.index} added from {self.hostname}')
                            await self.send({'op_type': 'response', 'status':'valid','hostname': {NAME}, 'time': data['time'] })
                            print(time.time())
                            

                    
                    if data['chain_length'] < len(blockchain.chain):
                        print('Node does not have longest chain')
                        await self.send({'op_type': 'blockchain','data': blockchain})
                                       
                if op_type == 'get_chain':
                    '''
                    connection wants the nodes current chain, must send entire chain to connection
                    '''
                    print(f'Connection from {self.hostname} wants this nodes chain')
                    message = {'op_type': 'blockchain','data': blockchain} 
                    await self.send(message)


                if op_type == 'chain_len':
                    '''
                    connection wants len of nodes blockchain, must send length back to connection
                    '''
                   
                    if data['status'] == 'get':
                        message = {'op_type': 'chain_len','status': 'post', 'data': len(blockchain.chain),'hostname': NAME}  
                        await self.send(message) 
                                         
                    if data['status'] == 'post': 
                        chain_length = data['data']
                        if chain_length < len(blockchain.chain): #Node will only send new block if it knows the reveing node has shorter chain
                            print('This Node has done more work')
                            await self.send({'op_type': 'new_block',
                                                    'chain_length': len(blockchain.chain),
                                                    'data': blockchain.last_block,
                                                    'time': time.time()})
                            
                            
                        else:
                            print('This Node doesnt have longest chain, get new chain')
                            await self.send({'op_type': 'get_chain'}) 
                    
                            
                        
                if op_type == 'blockchain':
                    '''
                    connection has sent entire blockchain, node must validate the chain, send back ack
                    '''
                    incoming_blockchain = data['data']
                    start_time = time.time()
                    valid = BlockChain.validate_chain(incoming_blockchain.chain)
                    end_time = time.time()
                    print(f'Validation took {end_time-start_time} seconds')
                    if not valid:
                        print(f'new blockchain is not valid')
                        await self.send({'op_type': 'response', 'status':'invalid'})
                        break
                                               
                    self.state = 'Connected'
                    string = f'Blockchain,number blocks{len(incoming_blockchain.chain)}, time,{end_time-start_time} \n\n'
                    res_file = open('results.txt','a')
                    res_file.write(string)
                    res_file.close()

                    print(f'new blockchain is length {len(incoming_blockchain.chain)}')
                    blockchain = incoming_blockchain
                    
                
                
                if op_type == 'transaction':
                    '''
                    node has received a new transaction and check that data is valid,
                     must sign it with private key
                    '''
                    global SIGNATURE
                    global Local_Power
                    print(f'transaction received')
                    transaction = data['data']
                    SIGNATURE = private_key.sign( pickle.dumps(transaction),
                                                     padding.PSS(
                                                         mgf=padding.MGF1(hashes.SHA256()),
                                                         salt_length=padding.PSS.MAX_LENGTH
                                                     ),
                                                     hashes.SHA256() )
                    #transaction = {'name': , 'amount': ,'time': }
                    result = time.localtime( time.time() )
                    if transaction['time'] > result.tm_hour: #transaction time must be strictly greater than current time
                        print('transaction valid')
                        Local_Power += transaction['amount']
                        WALLET[NAME][transaction['time']] += transaction['amount']
                        WALLET['Total_Power'] -= transaction['amount']
                        blockchain.add_new_transaction(WALLET)
                        print(f'Local Power is {Local_Power}')
                        if WALLET['Total_Power'] < 0:
                            print('Too much power')
                    
                    

                if op_type == 'response':
                    status = data['status']
                    if status == 'valid':
                        elapsed_time = time.time() - data['time']
                        string = f'Valid reply from {self.hostname} trip took: {elapsed_time}\n'
                        res_file = open('results.txt','a')
                        res_file.write(string)
                        res_file.close()
                        print(f'Valid reply from {self.hostname} trip took: {elapsed_time}')

                    #print(data)
                    if status == 'invalid':
                        print('invalid')


                #else: print(message)
                await asyncio.sleep(0)
        except RuntimeError:
            pass

        except websockets.exceptions.ConnectionClosed:
            print(f'Connection closed from {self.hostname}')
            await unregister(self)

        except:
            traceback.print_exc()
            await unregister(self)

        

    async def close(self):
        self.state = 'Disconnected'
        try:
            self.websocket.close()       
        except:
            traceback.print_exc()


class ServerHandler(ConnectionHandler):
    def __init__(self, websocket):
        self.websocket = websocket
       

class ClientHandler(ConnectionHandler):
    def __init__(self,uri):
        self.uri = uri


async def send_data(data):
    connection = list(CONNECTIONS)[0]

    if connection.state == 'Connected':
        data['name']=connection.hostname
        for _ in range(100):
            data = {'name': 'raspberrypi', 'amount': 1,'time': 23} 
            message = {'op_type': 'transaction','data': data}
            print('sending transaction')
            await connection.send(message)
            await asyncio.sleep(10)

async def mining_loop():
    global SIGNATURE
    global blockchain
    while True:      
        if blockchain.mine_block(SIGNATURE):           
            chain_len = len(blockchain.chain)           
            for connection in SERVER_CONNECTIONS:
                print({'op_type': 'chain_len','status': 'get', 'data': chain_len, 'hostname': connection.hostname})  
                await connection.send({'op_type': 'chain_len','status': 'get', 'data': chain_len, 'time':time.time(),'hostname': connection.hostname})


        await asyncio.sleep(0)
   


async def client_connect():
    uri = f'ws://192.168.0.173:5005'
    connection = ClientHandler(uri)
    await connection.login()
    if connection.state == 'Connected':
        CONNECTIONS.add(connection)
        asyncio.get_event_loop().create_task(connection.listener())
        #await send_data(data)
    await asyncio.sleep(0)                                            

async def port_scan():
    if not IP_ADDRESS[:3] == '192' and not IP_ADDRESS[:3] == '10' and not IP_ADDRESS[:3] == '172':
        print("Not a private network, shutting down")
        exit()
    
    ip_range = IP_ADDRESS.split('.')
    ip_range.pop()
    ip_range = '.'.join(ip_range)

    for i in range(5005,5020,1):
        if not i == int(PORT):
            uri = f'ws://192.168.0.160:{i}'      
            connection = ClientHandler(uri)
            await connection.login()
            if connection.state == 'Connected':
                CONNECTIONS.add(connection)
                asyncio.get_event_loop().create_task(connection.listener())
            await asyncio.sleep(0)


async def register_client(websocket, _):
    connection = ServerHandler(websocket)
    done = False
    while True:
        if not done: #while loop to make sure asyncio continues to run this process 
            if await connection.welcome():
                SERVER_CONNECTIONS.add(connection)
                done = True
        await asyncio.sleep(0) 

async def unregister(connection):
    await connection.close()
    try:
        CONNECTIONS.remove(connection)
    except:
        traceback.print_exc()


if __name__ == '__main__':
    start_server = websockets.serve(register_client, IP_ADDRESS, PORT)
    asyncio.get_event_loop().run_until_complete(start_server)
    asyncio.get_event_loop().run_until_complete(port_scan())
    asyncio.get_event_loop().create_task(mining_loop())
    asyncio.get_event_loop().run_forever()