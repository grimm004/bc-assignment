"""

Blockchain implementation and mining difficulty analysis for Task 1.
By wcrr51

Important note:
All hashes are generated from the byte-serialisations of the objects (not JSON).

Requires the external ecdsa and base58 libraries.
Optionally, matplotlib and numpy are required for analysis of mining difficulty.

In the example (at the end of this file), the following accounts are used (generated from the HTML page).

Party A
Address	    1DwWm1eVwwWTijVGN9kNAWCQWitmTFLEt4
Private Key	L2kG6xdPHH3uE5Nes4P3TfX6KzCn982gdPfhTncaZcfKuGcFgFYL

Party B
Address     15zxhoEsJw2xBMPUxVrBpepR36VZhUvzek
Private Key	L1VMTbXn8CBvbuJNHMTEX4qYAb7mFUtQeqVpCrDUkMCXfUmV1Vsh

Party C
Address	    1DnNkHkmYZrJzmqSRVb967ZZs4un2RwTet
Private Key	KwkykaU9evqi37qP8aEDimJM5zxDuGVrbr9E5LHkb9o4EZjMkT24

"""

from typing import List, Tuple, Optional, Dict, Any, Union
import sys
import json
from datetime import datetime
from hashlib import sha256
import time
import ecdsa
import base58

# Endianness of serialised numbers
ENDIANNESS: str = "big"
# 0 or None for current time, or a number of seconds
TIME: Optional[int] = 1642257000


def get_time() -> int:
    return TIME if TIME else int(time.time())


def hash_sha256(data: bytes) -> bytes:
    """
    Hash data with SHA256 and return its bytes digest.

    :param data: Data to hash
    :return: bytes-digest of the hashed data
    """

    return sha256(data).digest()


def serialise(number: int, size: int) -> bytes:
    """
    Serialise an unsigned integer

    :param number: Unsigned integer to serialise
    :param size: Number of bytes to serialise the number to
    :return: bytes representation of the number
    """

    return number.to_bytes(size, ENDIANNESS, signed=False)


def deserialise(data: bytes, offset: int = 0, size: int = -1) -> int:
    """
    Deserialise an unsigned integer

    :param data: Data to deserialise
    :param offset: Start position of the number within the data
    :param size: Number of bytes to deserialise from the offset within the data
    :return: deserialised integer
    """

    if size == -1:
        size = len(data)
    return int.from_bytes(data[offset:offset + size], ENDIANNESS, signed=False)


def decode_b58(data: str) -> bytes:
    """
    Decode a base 58-encoded string to a byte array.

    :param data: Base 58-encoded string to decode.
    :return: bytes representation of encoded data
    """

    return base58.b58decode(data.encode("utf-8"))


def encode_b58(data: bytes) -> str:
    """
    Encode a byte array into a base 58-encoded string.

    :param data: Data to encode.
    :return: base 58 representation of data
    """

    return base58.b58encode(data).decode("utf-8")


class Transaction:
    VERSION = 1

    def __init__(self):
        self.inputs: List[bytes] = []
        self.outputs: List[Tuple[bytes, int]] = []
        self.address_private_keys: Dict[bytes, bytes] = {}
        self.signable: bool = True
        self.signatures: Dict[bytes, bytes] = {}
        self.hash = bytes(32)

    def add_signed_input(self, address: bytes, signature: Optional[bytes] = None) -> "Transaction":
        """
        Add signed input to the transaction

        :param address: Public address of the input
        :param signature: Signature for input
        :return: Current transaction
        """

        self.signable = False
        if signature:
            self.signatures[address] = signature
        self.inputs.append(address)
        return self

    def add_input(self, address: bytes, private_key: bytes) -> "Transaction":
        """
        Add a signable input to the transaction.

        :param address: Public address of the input
        :param private_key: Private key corresponding to the input address
        :return: Current transaction
        """

        self.address_private_keys[address] = private_key
        self.inputs.append(address)
        return self

    def add_output(self, address: bytes, amount: int) -> "Transaction":
        """
        Add an output to the transaction.

        :param address: Public address for which to send the amount
        :param amount: Number of minimum-unit coins to send to the address
        :return: Current transaction
        """

        self.outputs.append((address, amount))
        return self

    def serialise(self, signed: bool = True, save_hash: bool = False, save_signatures: bool = True) -> bytes:
        """
        Serialise the transaction to bytes.

        :param signed: True to include input signatures in the serialised transaction data
        :param save_hash: True if the hash should be saved to the transaction
        :param save_signatures: If True and signed, save the signatures to the transaction
        :return: byte-serialised representation of the transaction
        """

        if not self.signable and signed:
            raise ValueError("Transaction is not signable.")

        # If the private keys for the inputs are specified,
        # fetch a unsigned hash of the serialised representation of the transaction
        hashed_serialised_unsigned: Optional[bytes] = self.compute_hash(False, save_hash) if signed else None

        input_data = bytearray(len(self.inputs))
        for address in self.inputs:
            # Add the public address to the input data
            input_data.extend(address)

            # If these inputs are to be signed...
            if signed:
                # Generate the input signature from the private key corresponding to the current public address
                signing_key = ecdsa.SigningKey.from_string(
                    self.address_private_keys[address],
                    curve=ecdsa.SECP256k1,
                    hashfunc=sha256
                )

                signature: bytes = signing_key.sign_digest(hashed_serialised_unsigned)
                # Add the signature to the input data
                input_data.extend(signature)

                if save_signatures:
                    self.signatures[address] = signature

        output_data = bytearray(len(self.outputs))
        for address, amount in self.outputs:
            output_data.extend(address + serialise(amount, 8))

        # Serialise the transaction (version, input count, inputs, output count, outputs)
        return \
            serialise(self.VERSION, 4) + \
            serialise(len(input_data), 4) + \
            bytes(input_data) + \
            serialise(len(output_data), 4) + \
            bytes(output_data)

    def to_object(self) -> Any:
        """
        Get a data-only representation of the transaction.

        :return: Data-only representation of the current transaction
        """

        hash_ = self.compute_hash(True, False).hex()

        return {
            "VERSION": self.VERSION,
            "inputs": [
                {
                    "public_key": input_.hex(),
                    "signature": self.signatures[input_].hex()
                }
                if self.signatures else
                input_.hex() for input_ in self.inputs
            ],
            "outputs": {output.hex(): amount for output, amount in self.outputs},
            "hash": hash_
        }

    def serialise_json(self, **kwargs) -> str:
        """
        Serialise the transaction to a JSON representation.

        :param kwargs: keyword arguments to be given to the json converter
        :return: JSON representation of the current transaction
        """

        return json.dumps(self.to_object(), sort_keys=True, **kwargs)

    def compute_hash(self, signed: bool = True, save: bool = False, save_signatures: bool = True) -> bytes:
        """
        Compute the hash of the transaction.

        :param signed: True if the hash should be of the signed transaction
        :param save: True if the hash should be saved to the transaction
        :param save_signatures: If True and signed, save the signatures to the transaction
        :return: Hash of the current transaction
        """

        # Serialise the transaction and calculate its hash
        hashed = hash_sha256(self.serialise(signed, save, save_signatures))
        if save:
            self.hash = hashed
        return hashed

    def verify(self, verbose: bool = False) -> bool:
        """
        Verify transaction signatures.

        :param verbose: True if verification information should be output to the console
        :return: True if the input signatures are valid and match the transaction
        """

        if verbose:
            print(f"\t\t- Checking validity of transaction '{self.hash.hex()}'")

        if self.inputs and not self.signatures:
            if verbose:
                print(f"\t\t\t\u2718 Number of available signatures does not match number of inputs.")
            return False
        if verbose:
            print(f"\t\t\t\u2714 Number of available signatures matches number of inputs.")

        hashed_serialised_unsigned: bytes = self.compute_hash(False, False)

        for public_key, signature in self.signatures.items():
            vk = ecdsa.VerifyingKey.from_string(
                public_key,
                curve=ecdsa.SECP256k1,
                hashfunc=sha256
            )
            try:
                vk.verify_digest(signature, hashed_serialised_unsigned)
            except ecdsa.keys.BadSignatureError:
                if verbose:
                    print(f"\t\t\t\u2718 Invalid signature for address beginning '{public_key[:16].hex()}'.")
                return False
            if verbose:
                print(f"\t\t\t\u2714 Signature authenticated for address beginning '{public_key[:16].hex()}'.")

        if verbose:
            print(f"\t\t\u2714 Successfully validated transaction.")

        return True

    @staticmethod
    def coin_creation(address_to: bytes, amount: int) -> "Transaction":
        """
        Create a coin creation transaction.

        :param address_to: Address to send the created coin to
        :param amount: Number of minimum-unit coins to send to the address
        :return: Created transaction
        """

        # Only add transaction output (no input)
        transaction = Transaction() \
            .add_output(address_to, amount)
        return transaction

    @staticmethod
    def one_to_one_transfer(address_from: bytes, private_key_from: bytes, address_to: bytes, amount: int):
        """
        Create a one-to-one coin transaction.

        :param address_from: Address to send the coins from
        :param private_key_from: Private key of the input address
        :param address_to: Address to send the coins to
        :param amount: Number of minimum-unit coins to transfer
        :return: Created transaction
        """

        transaction = Transaction() \
            .add_input(address_from, private_key_from) \
            .add_output(address_to, amount)
        return transaction

    @staticmethod
    def one_to_many_transfer(address_from: bytes, private_key_from: bytes, to: List[Tuple[bytes, int]]):
        """
        Create a one-to-one coin transaction.

        :param address_from: Address to send the coins from
        :param private_key_from: Private key of the input address
        :param to: List of tuples specifying coin recipients and the amount
        :return: Created transaction
        """

        transaction = Transaction() \
            .add_input(address_from, private_key_from)
        for address_to, amount in to:
            transaction.add_output(address_to, amount)
        return transaction

    @staticmethod
    def deserialise(data: bytes, signed: bool = True, offset: int = 0) -> Tuple[Optional["Transaction"], int]:
        """
        Deserialise a transaction from bytes.

        :param data: The data from which the transaction should be deserialised
        :param signed: True if the transaction is signed
        :param offset: Offset within data to start deserialising from
        :return: Deserialised transaction and finish offset within data
        """

        position: int = offset

        transaction = Transaction()

        # Skip version
        version = data[position:position + 4]
        assert version == Transaction.VERSION
        position += 4

        input_count = deserialise(data, position, 4)
        position += 4
        signatures: Dict[bytes, bytes] = {}
        for i in range(input_count):
            address = data[position:position + 32]
            position += 32

            signature = None

            if signed:
                signature = data[position:position + 64]
                position += 64
                signatures[address] = signature

            transaction.add_signed_input(address, signature)

        output_count = deserialise(data, position, 4)
        position += 4
        for i in range(output_count):
            address = data[position:position + 32]
            position += 32
            amount = deserialise(data, position, 8)
            position += 8
            transaction.add_output(address, amount)

        if signed:
            # Verify the deserialised transaction
            if not transaction.verify():
                return None, position - offset

        return transaction, position - offset


class Block:
    VERSION = 1
    MAGIC = "WCRR".encode("utf-8")

    def __init__(self, block_id: int, hash_previous_block: bytes, difficulty: int, timestamp: int):
        """
        :param block_id: Block number
        :param hash_previous_block: Hash of previous block header
        :param difficulty: Number of leading zeros for proof of work
        :param timestamp: Timestamp of blockchain creation
        """

        self.id: int = block_id
        self.hash_previous_block: bytes = hash_previous_block
        self.nonce: int = 0
        self.difficulty: int = difficulty
        self.timestamp: int = timestamp
        self.transactions: List[Transaction] = []
        self.hash = bytes(32)
        self.merkle_root_hash = bytes(32)

    def serialise_header(self, save_merkle: bool = False) -> bytes:
        """
        Serialise the block header to binary.

        :return: byte-serialised representation of the block header
        """

        merkle_root_hash: bytes = self.compute_merkle_root_hash(save_merkle)

        # Serialisation order: Version, ID, previous block hash, merkle root hash, timestamp, difficulty, and nonce
        return \
            serialise(self.VERSION, 4) + \
            serialise(self.id, 4) + \
            self.hash_previous_block + \
            merkle_root_hash + \
            serialise(self.timestamp, 4) + \
            serialise(self.difficulty, 4) + \
            serialise(self.nonce, 4)

    def serialise(self, save_merkle: bool = False) -> bytes:
        """
        Serialise the block to binary.

        :param save_merkle: True if the Merkle root hash should be saved to the block
        :return: byte-serialised representation of the block
        """

        header: bytes = self.serialise_header(save_merkle)

        transactions: bytearray = bytearray()
        for transaction in self.transactions:
            transactions.extend(transaction.serialise())

        remainder: bytes = header + serialise(len(transactions), 4) + bytes(transactions)
        return self.MAGIC + serialise(len(remainder), 4) + remainder

    def to_object(self) -> Any:
        """
        Get a data-only representation of the block.

        :return: Data-only representation of the current block
        """

        return {
            "VERSION": self.VERSION,
            "id": self.id,
            "hash_previous_block": self.hash_previous_block.hex(),
            "nonce": self.nonce,
            "difficulty": self.difficulty,
            "timestamp": datetime.utcfromtimestamp(self.timestamp).isoformat(),
            "hash": self.compute_hash(False).hex(),
            "transactions": [transaction.to_object() for transaction in self.transactions]
        }

    def serialise_json(self, **kwargs) -> str:
        """
        Serialise the block to a JSON representation.

        :param kwargs: keyword arguments to be given to the json converter
        :return: JSON representation of the current block
        """

        return json.dumps(self.to_object(), sort_keys=True, **kwargs)

    def add_transaction(self, transaction: Transaction):
        """
        Add a transaction to the block.

        :param transaction: Transaction to append to the block
        """

        self.transactions.append(transaction)

    def compute_merkle_root_hash(self, save: bool = False) -> bytes:
        """
        Compute the Merkle root hash for the transactions.

        :return: Merkle root hash of all transactions
        """

        if not len(self.transactions):
            if save:
                self.merkle_root_hash = bytes(32)
            return bytes(32)

        hashes: List[bytes] = [transaction.compute_hash(False, save) for transaction in self.transactions]
        while len(hashes) > 1:
            if len(hashes) % 2 == 1:
                hashes.append(hashes[-1])

            next_hashes: List[bytes] = []
            for i in range(0, len(hashes), 2):
                next_hashes.append(hashes[i] + hashes[i + 1])

            hashes = next_hashes

        if save:
            self.merkle_root_hash = hashes[0]

        return hashes[0]

    def mine(self) -> "Block":
        """
        Demonstrate proof of work by finding the nonce value such that the number of leading zeros in
        the block hash matches the required difficulty.

        :return: Current block
        """

        while not self.compute_hash(True).hex().startswith("0" * self.difficulty):
            self.nonce += 1
        return self

    def compute_hash(self, save: bool = False) -> bytes:
        """
        Compute the hash of the block header.

        :param save: True if the hash (and Merkle root hash) should be saved to the block
        :return: Hash of the current block header
        """

        # Serialise the block and calculate its hash
        hashed = hash_sha256(self.serialise_header(save))
        if save:
            self.hash = hashed
        return hashed

    def verify(self, verbose: bool = False) -> bool:
        """
        Verify the block hash is correct, and has been mined to the specified difficulty

        :param verbose: True if verification information should be output to the console
        :return: True if the block is valid, False if not
        """

        block_hash = self.compute_hash(False)
        merkle_root_hash = self.compute_merkle_root_hash(False)

        if block_hash != self.hash:
            if verbose:
                print(f"\t\u2718 The hash of block {self.id} does not match the stored hash.")
            return False
        if verbose:
            print(f"\t\u2714 The hash of block {self.id} matches the stored hash.")

        if not block_hash.hex().startswith("0" * self.difficulty):
            if verbose:
                print(f"\t\u2718 Block {self.id} does not have sufficient proof of work.")
            return False
        if verbose:
            print(f"\t\u2714 Block {self.id} has sufficient proof of work.")

        if merkle_root_hash != self.merkle_root_hash:
            if verbose:
                print(f"\t\u2718 The Merkle root hash of block {self.id} does not match the stored Merkle root hash.")
            return False
        if verbose:
            print(f"\t\u2714 The Merkle root hash of block {self.id} matches the stored Merkle root hash.")

        if not all([transaction.verify(verbose) for transaction in self.transactions]):
            if verbose:
                print(f"\t\u2718 A transaction in block {self.id} failed to validate.")
            return False
        if verbose:
            print(f"\t\u2714 All transactions in block {self.id} successfully validated.")

        return True

    def __repr__(self):
        return f"Block({self.id}, {self.compute_hash().hex()}, {len(self.transactions)})"

    def __str__(self):
        return self.__repr__()

    @staticmethod
    def from_previous(previous: "Block") -> "Block":
        """
        Create an empty block from a previous block.

        :param previous: Previous block in the chain.
        :return: New transaction-less block inheriting from the previous block.
        """
        return Block(previous.id + 1, previous.compute_hash(), previous.difficulty, get_time())

    @staticmethod
    def genesis(difficulty: int) -> "Block":
        """
        Create an empty genesis block.

        :param difficulty: Block mining difficulty.
        :return: An transaction-less genesis block.
        """
        return Block(0, bytes(32), difficulty, get_time())

    @staticmethod
    def deserialise(data: bytes, offset: int) -> Tuple["Block", int]:
        """
        Deserialise a block from bytes.

        :param data: The data from which the block should be deserialised
        :param offset: Offset within data to start deserialising from
        :return: Deserialised block and finish offset within data
        """

        position: int = offset

        # Verify magic numbers
        magic = data[position:position + 4]
        assert magic == Block.MAGIC
        position += 4

        # Skip remainder length
        remainder_length = deserialise(data, position, 4)
        position += 4

        # Deserialise header
        # Version
        version = deserialise(data, position, 4)
        assert version == Block.VERSION
        position += 4

        # ID
        block_id = deserialise(data, position, 4)
        position += 4

        # Previous block hash
        hash_previous_block = data[position:position + 32]
        position += 32

        # Merkle root hash for transactions
        merkle_root_hash = data[position:position + 32]
        position += 32

        # Timestamp
        timestamp = deserialise(data, position, 4)
        position += 4

        # Difficulty
        difficulty = deserialise(data, position, 4)
        position += 4

        # Nonce
        nonce = deserialise(data, position, 4)
        position += 4

        block = Block(block_id, hash_previous_block, difficulty, timestamp)
        block.nonce = nonce
        block.merkle_root_hash = merkle_root_hash

        transaction_count = deserialise(data, position, 4)
        for i in range(transaction_count):
            transaction, transaction_size = Transaction.deserialise(data, True, position)
            block.add_transaction(transaction)
            position += transaction_size

        return block, offset + 4 + remainder_length


class Blockchain:
    VERSION = 1

    def __init__(self, difficulty: int):
        self.transaction_queue: List[Transaction] = []
        self.blocks: List[Block] = []
        self.difficulty = difficulty

    def add_transaction(self, transaction: Transaction) -> None:
        """
        Add a transaction to the transaction queue.

        :param transaction: transaction to add
        """

        self.transaction_queue.append(transaction)

    def verify(self, verbose: bool = False) -> bool:
        """
        Verify the integrity of the blockchain.

        :param verbose: True if verification information should be output to the console
        :return: True if the blockchain is valid, False if not
        """

        if verbose:
            print(f"Verifying blockchain with {len(self.blocks)} blocks...\n")

        # Check that there are blocks to verify
        if not self.blocks:
            print("No blocks found.")
            return True

        # Compute the hash of the first block
        first_block = self.blocks[0]

        print(f"- Checking validity of genesis block...")

        if first_block.id != 0:
            print(f"\u2718 ID of genesis block is not 0 (received {first_block.id}).")
            return False

        previous_hash = first_block.compute_hash()
        if not first_block.verify(verbose):
            if verbose:
                print(f"\u2718 Genesis block failed verification.")
            return False
        if verbose:
            print(f"\u2714 Genesis block passed validation.\n")

        for i, block in enumerate(self.blocks[1:], 1):
            if i != block.id:
                if verbose:
                    print(f"\u2718 Block ID mismatch (should be ID {i}, received {block.id}).")
                return False

            print(f"- Checking validity of block {block.id}...")

            block_hash = block.compute_hash()

            # Check previous block hash matches
            if block.hash_previous_block != previous_hash:
                if verbose:
                    print(f"\t\u2718 Block {block.id}'s previous hash does not match that of the previous block.")
                return False
            if verbose:
                print(f"\t\u2714 Block {block.id}'s previous hash matches that of the previous block.")

            if not block.verify(verbose):
                if verbose:
                    print(f"\u2718 Block {block.id} failed verification.")
                return False
            if verbose:
                print(f"\u2714 Block {block.id} passed validation.\n")

            previous_hash = block_hash

        return True

    def create_block(
            self,
            mine: bool = True,
            clear_pending: bool = True,
            add_to_chain: bool = True
    ) -> Optional[Block]:
        """
        Create a block with the pending transactions.

        :param mine: True if the block should be mined
        :param clear_pending: True if the queue of pending transactions should be cleared
        :param add_to_chain: True if the block should be added to the blockchain
        :return: if successful, the newly created block, if not, then None
        """

        # If there are no pending transactions, do not create a block and return false
        if not self.transaction_queue:
            return None

        # Create a genesis block if the chain is empty, or create one using the last block in the chain
        new_block = Block.from_previous(self.tail) if self.blocks else Block.genesis(self.difficulty)

        # Add each transaction to the block
        for transaction in self.transaction_queue:
            new_block.add_transaction(transaction)

        if mine:
            # Mine the new block
            new_block.mine()

        if add_to_chain:
            # Add the block to the chain
            self.blocks.append(new_block)

        if clear_pending:
            # Clear the list of pending transactions
            self.transaction_queue.clear()

        return new_block

    @property
    def tail(self) -> Optional[Block]:
        """
        Last block in the blockchain.

        :return: the last block in the chain
        """

        return self.blocks[-1] if self.blocks else None

    def serialise(self) -> bytes:
        """
        Serialise the blockchain to binary.

        :return: byte-serialised representation of the blockchain
        """

        block_data = bytearray()
        for block in self.blocks:
            block_data.extend(block.serialise())
        return \
            serialise(self.VERSION, 4) + \
            serialise(len(block_data), 4) + \
            block_data

    def to_object(self) -> Any:
        """
        Get a data-only representation of the blockchain.

        :return: Data-only representation of the current blockchain
        """

        return {
            "VERSION": self.VERSION,
            "blocks": [block.to_object() for block in self.blocks],
            "pending_transactions": [transaction.to_object() for transaction in self.transaction_queue]
        }

    def serialise_json(self, **kwargs) -> str:
        """
        Serialise the blockchain to a JSON representation.

        :param kwargs: keyword arguments to be given to the json converter
        :return: JSON representation of the current blockchain
        """

        return json.dumps(self.to_object(), sort_keys=True, **kwargs)


class Account:
    def __init__(self, address_b58: str, private_key_b58: str):
        """
        :param address_b58: Address in base 58 encoding
        :param private_key_b58: Private key in base 58 encoding
        """

        self.address_b58: str = address_b58
        self.private_key_b58: str = private_key_b58

        self.address: bytes = decode_b58(address_b58)
        self.private_key: bytes = decode_b58(private_key_b58)[1:-5]
        self.public_key: bytes = ecdsa.SigningKey.from_string(
            self.private_key,
            curve=ecdsa.SECP256k1
        ).verifying_key.to_string()


def main() -> int:
    accounts: Dict[str, Account] = {
        "A": Account("1DwWm1eVwwWTijVGN9kNAWCQWitmTFLEt4", "L2kG6xdPHH3uE5Nes4P3TfX6KzCn982gdPfhTncaZcfKuGcFgFYL"),
        "B": Account("15zxhoEsJw2xBMPUxVrBpepR36VZhUvzek", "L1VMTbXn8CBvbuJNHMTEX4qYAb7mFUtQeqVpCrDUkMCXfUmV1Vsh"),
        "C": Account("1DnNkHkmYZrJzmqSRVb967ZZs4un2RwTet", "KwkykaU9evqi37qP8aEDimJM5zxDuGVrbr9E5LHkb9o4EZjMkT24")
    }

    # Create a new blockchain instance with a difficulty of 5
    blockchain = Blockchain(5)

    # Add a coin creation transaction to put 5000 min unit coins into A's account
    blockchain.add_transaction(Transaction.coin_creation(accounts["A"].public_key, 5000))
    # Add a coin creation transaction to put 10000 min unit coins into B's account
    blockchain.add_transaction(Transaction.coin_creation(accounts["B"].public_key, 10000))
    # Add a coin creation transaction to put 2000 min unit coins into C's account
    blockchain.add_transaction(Transaction.coin_creation(accounts["C"].public_key, 2000))
    print("Creating and mining block... ", end="")
    # Create a new block
    blockchain.create_block()
    print("Done!")

    print(f"Genesis Block:\n{blockchain.tail.serialise_json(indent=4)}", end="\n\n")

    # Transfer 1000 min unit coins from A to B, and 2000 min unit coins from A to C
    blockchain.add_transaction(
        Transaction.one_to_many_transfer(
            accounts["A"].public_key, accounts["A"].private_key, [
                (accounts["B"].public_key, 1000),
                (accounts["C"].public_key, 2000)
            ]
        )
    )
    # Transfer 2000 min unit coins from B to A
    blockchain.add_transaction(
        Transaction.one_to_one_transfer(
            accounts["B"].public_key, accounts["B"].private_key, accounts["C"].public_key, 2000
        )
    )
    # Transfer 10 min unit coins from C to B
    blockchain.add_transaction(
        Transaction.one_to_one_transfer(
            accounts["C"].public_key, accounts["C"].private_key, accounts["B"].public_key, 10
        )
    )
    print("Creating and mining block... ", end="")
    # Create a new block
    blockchain.create_block()
    print("Done!")

    print(f"Block #{len(blockchain.blocks) - 1}:\n{blockchain.tail.serialise_json(indent=4)}", end="\n\n")

    # Verify blockchain integrity and validity...
    print("Blockchain successfully validated!" if blockchain.verify(verbose=True) else "Blockchain validation failed.")

    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("Could not find matplotlib for mining difficulty analysis, exiting.")
        return 0

    def plot(
            diffs: List[int],
            values: List[Union[float, int]],
            title: str,
            yscale: str,
            ylabel: str,
            filename: str
    ):
        plt.plot(diffs, values)
        plt.gca().xaxis.get_major_locator().set_params(integer=True)
        plt.title(title)
        plt.yscale(yscale)
        plt.ylabel(ylabel)
        plt.xlabel("Difficulty (leading zeros in block hash)")
        plt.savefig(filename)
        plt.clf()

    difficulties: List[int] = []
    times: List[Tuple[float, float]] = []
    mean_nonces: List[int] = []

    for difficulty in range(11):
        print(f"Analysing mining difficulty {difficulty}...")

        for block in blockchain.blocks:
            # Reset block nonce values
            block.nonce = 0
            # Set block difficulty to the current one being considered
            block.difficulty = difficulty

        start_time = time.time()
        block_times = []
        nonces = []

        for block in blockchain.blocks:
            block_start_time = time.time()
            time.sleep(0.0000000001)
            block.mine()
            block_end_time = time.time()

            block_time = block_end_time - block_start_time
            block_times.append(block_time)
            nonces.append(block.nonce)

            print(f"Block {block.id} mining time: {block_time:.4f} s, nonce: {block.nonce}")

        end_time = time.time()

        total_time = end_time - start_time
        mean_time = sum(block_times) / len(block_times)
        mean_nonce = int(sum(nonces) / len(nonces))

        print(f"Overall time taken: {total_time:.4f} s\n"
              f"Average block mine time: {mean_time:.4f} s\n"
              f"Average nonce: {mean_nonce}\n")

        difficulties.append(difficulty)
        times.append((total_time, mean_time))
        mean_nonces.append(mean_nonce)

        if difficulty < 2:
            continue

        plot(
            difficulties, mean_nonces,
            "Mean Nonce Value by Difficulty",
            "linear",
            "Mean Nonce Value",
            "difficulty-mean-nonces-linear.png"
        )

        plot(
            difficulties, list(map(lambda x: x[0], times)),
            "Total Mine Time by Difficulty",
            "linear",
            "Total Mine Time (s)",
            "difficulty-total-times-linear.png"
        )

        plot(
            difficulties, list(map(lambda x: x[1], times)),
            "Mean Mine Time by Difficulty",
            "linear",
            "Mean Block Mine Time (s)",
            "difficulty-mean-times-linear.png"
        )

        plot(
            difficulties, mean_nonces,
            "Mean Nonce Value by Difficulty",
            "symlog",
            "Mean Nonce Value",
            "difficulty-mean-nonces-symlog.png"
        )

        plot(
            difficulties[1:], list(map(lambda x: x[0], times[1:])),
            "Total Mine Time by Difficulty",
            "log",
            "Total Mine Time (s)",
            "difficulty-total-times-log.png"
        )

        plot(
            difficulties[1:], list(map(lambda x: x[1], times[1:])),
            "Mean Mine Time by Difficulty",
            "log",
            "Mean Block Mine Time (s)",
            "difficulty-mean-times-log.png"
        )

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Keyboard Interrupt")
