from client import Client
from node import Node
import time
from utils import OP

if __name__ == "__main__":
    #  In TOR, these nodes would be selected randomly from the Directory of nodes
    node1 = Node("node_1")
    node2 = Node("node_2")
    node3 = Node("node_3")
   

    node_table = {"node_1": node1, "node_2": node2, "node_3": node3}
    # Create the nodes that will be used in creating a circuit
    client = Client(node_table)

    print("Created nodes to build the circuit: " +
          node1.id + ", " + node2.id +", " + node3.id)
    print("Building the circuit:")

    # send a CREATE message from Client to Node 1. Node 1 decrypts it, and
    # sends Client back a CREATED message with its half of the DHKE. Client
    # creates the key and saves it.
    client.send_message("node_1", op=OP.CREATE)
    client.send_message("node_2", op=OP.CREATE)
    client.send_message("node_3", op=OP.CREATE)

    # # Extend the circuit to node 2. Node1 sends a create message to node2
    # # with the encrypted first half of DHKE. node2 replies with a CREATED
    # # to node1, and then node1 replies to client with an EXTENDED.
    # time.sleep(5)
    client.send_message("node_1 node_2", op=OP.EXTEND)

    # # TODO try to view DHKE2 from node1 (should fail cuz no private key)
    # time.sleep(5)
    # client.send_EXTEND(node2, msg=client.DHKE3.public_key, create=node3)
    # client.send_message(node1, op=OP.EXTEND) #Possible issue with extend not forwarding everything to the next node, but node1 everytime.

    # # Circuit complete. Now it's time to relay messages through.
    # client.relay("Wooo - no one knows who sent this msg!")
    # # TODO try to determine who client is from node3 (should fail as only node1
    # # knows who the client is)

    ##
