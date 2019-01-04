defmodule Server do
  use GenServer
  @moduledoc """
  This is the Server Module where the GenServers are created.
  Each genserver will work as a separate node(user or miner) 
  in the bitcoin network and will have their own wallet 
  (private/public key pair) and their own copy of the ledger.
  All the handle methods and server methods are defined here.
  """

  # Starts a genserver.
  def start() do
    GenServer.start_link(__MODULE__, :done) 
  end

  # Initializes the state of the nodes.
  def init() do
    {:ok, { 0, 0, []} }
  end

  # Initializes the wallet
  def handle_cast({:set_key, private_key, public_key}, state) do
    {:noreply, {private_key, public_key, []}}
  end

  # Starts mining the block for a miner
  def handle_cast({:mine, node_list, private_key, public_key, block}, state) do
    IO.inspect self, label: "Started mining"
    IO.puts "------"
    transactions = elem(block, 1)
    nonce = ProofofWork.generation(transactions)
    IO.inspect self, label: "Mining Finished by"
    Main.broadcastBlock(node_list, block, nonce, self)

    current_ledger = elem(state, 2)
    last_block_previous_hash = elem(List.last(current_ledger), 0)
    this_block_previous_hash = elem(block, 0)
    if last_block_previous_hash != this_block_previous_hash do
      IO.inspect self, label: "Miner is adding Block to it's own ledger for"
      updated_ledger = current_ledger ++ [block]
      {:noreply, {private_key, public_key, updated_ledger}}
    else
      IO.inspect self, label: "Other miner already added the block to this miner"
      {:noreply, {private_key, public_key, current_ledger}}
    end
  end

  # Verifies and adds the block to the ledger/blockchain 
  def handle_cast({:add_block, block, nonce, miner_pid, node_list}, state) do
    private_key = elem(state, 0)
    public_key = elem(state, 1)
    current_ledger = elem(state, 2)
    pid0 = elem(Enum.at(node_list,0), 1)
    if pid0 != self do
      current_ledger = GenServer.call(pid0, {:fetch_ledger})
    else
      current_ledger = elem(state, 2)
    end

    if Main.verifyProofOfWork(block, nonce, miner_pid) do
      last_block_previous_hash = elem(List.last(current_ledger), 0)
      last_block_current_hash = elem(List.last(current_ledger), 1)
      new_block_previous_hash = elem(block, 0)
      IO.inspect "WHYYYYYYYYYYYYYYYYY"
      dec = last_block_previous_hash != new_block_previous_hash and last_block_current_hash == new_block_previous_hash
      if dec do
        IO.inspect self, label: "Block is being added to the ledger for" 
        updated_ledger = current_ledger ++ [block]
        {:noreply, {private_key, public_key, updated_ledger}}
      else
        IO.inspect self, label: "Block is already there for"
        {:noreply, state}
      end
    else
      IO.puts "Block is invalid"
      {:noreply, {private_key, public_key, current_ledger}}
    end
  end

  # Adds the genesis block to the ledger/blockchain
  def handle_cast({:add_genblock, private_key, public_key, block}, state) do
    current_ledger = elem(state, 2)
    updated_ledger = current_ledger ++ [block]
    {:noreply, {private_key, public_key, updated_ledger}}
  end

  # Fetches the private key
  def handle_call({:fetch_priv},_from, state) do
    private_key = elem(state,0)
    {:reply, private_key, state}
  end

  # Fetches the public key
  def handle_call({:fetch_public},_from, state) do
    public_key = elem(state,1)
    {:reply, public_key, state}
  end

  # Fetches the ledger
  def handle_call({:fetch_ledger},_from, state) do
    ledger = elem(state,2)
    {:reply, ledger, state}
  end

end


defmodule Main do

  @moduledoc """
  The Main module which contains the main and other helper functions.
  The main function calls all the appropriate functions in order
  to create nodes, initialize wallets and start mining. The first 
  argument is the number of nodes or users and the second argument 
  is the number of miners in the network.
  """
  def main(args) do
    if(length(args)!=2) do
      IO.puts("Invalid number of arguments provided!")
    else
      {numNodes, d1} = Integer.parse(Enum.at(args, 0))
      {numMiners, d1} = Integer.parse(Enum.at(args, 1))
      if numMiners>=numNodes do
        IO.puts "Too many miners!!"
      else 
        node_list = createNodes(numNodes)
        createWallet(node_list)
        createGenesisBlock(node_list)
        miningTest(node_list, numMiners)
        IO.puts("Going to sleep")
        :timer.sleep(3000)
        IO.puts("Out of sleep")
        IO.inspect displayLedger(elem(Enum.at(node_list,0), 1))
      end
    end 
  end

  # This function creates the number of nodes in the network 
  # given by the user. 
  def createNodes(n) do
    node_list = Enum.map(1..n, fn(x) -> Server.start end)
  end

  # This function creates wallet for every user/node in the 
  # network.
  def createWallet(node_list) do
    Enum.map(node_list, fn(x) -> 
      pid = elem(x, 1)
      private_key = PrivateKey.generate
      public_key = PrivateKey.to_public_key(private_key)
      GenServer.cast(pid, {:set_key, private_key, public_key})
      end)
  end

  # This function displays the current ledger for a node.
  def displayLedger(pid) do
    current_ledger = GenServer.call(pid, {:fetch_ledger})
    # IO.inspect current_ledger
  end

  # This function creates the genesis block and add it to 
  # the ledger for the entire network
  def createGenesisBlock(node_list) do
    transactions = Enum.reduce(node_list, [], fn(x), acc -> 
        pid = elem(x, 1)
        public_key = GenServer.call(pid, {:fetch_public})
        transaction = ["No Inputs (Newly Generated Coins)", public_key, 100]
        acc ++ [transaction]
    end)
    this_hash = hashify(transactions)
    block = {nil, this_hash, transactions}
    Enum.map(node_list, fn(x) -> 
      pid = elem(x, 1)
      private_key = GenServer.call(pid, {:fetch_priv})
      public_key = GenServer.call(pid, {:fetch_public})
      GenServer.cast(pid, {:add_genblock, private_key, public_key, block})
    end)
  end

  # This functions broadcasts the block to all the users/nodes once the miner is
  # finished with mining on it.
  def broadcastBlock(node_list, block, nonce, miner_pid) do
    Enum.map(node_list, fn(x) -> 
      pid = elem(x, 1)
      if miner_pid != pid do
        GenServer.cast(pid, {:add_block, block, nonce, miner_pid, node_list})
      end
    end)
  end

  # This functions verifies the proof of work with the nonce.
  def verifyProofOfWork(block, nonce, miner_pid) do
    transactions = elem(block, 2)
    hashed_transaction = hashify(transactions)
    result = hashed_transaction <> nonce
    solution = hashify(result)
    if String.starts_with?(solution, "00") do
      IO.inspect miner_pid, label: "proof of work is correct by"
      true
    else
      IO.inspect miner_pid, label: "proof of work is wrong by"
      false
    end
  end

  # This function creates the block with the transactions sent by the
  # miner.
  def createBlock(transaction, pid, miner_public_key, node_list) do
    pid0 = elem(Enum.at(node_list,0), 1)
    current_ledger = GenServer.call(pid0, {:fetch_ledger})
    last_block = List.last(current_ledger)
    previous_hash = elem(last_block, 1)
    transactions = [transaction] ++ [["No Inputs (Newly Generated Coins)", miner_public_key, 25]]
    this_hash = hashify(transactions)
    IO.puts "Block created"
    block = {previous_hash, this_hash, transactions}
    block
  end
  
  # This function generates random transactions and broadcasts it to
  # all the users.
  def transact(node_list, miner_pid) do
    miner_public_key = GenServer.call(miner_pid, {:fetch_public})
    pids = Enum.take_random(node_list, 2)
    sender_pid = elem(Enum.at(pids, 0),1)
    receiver_pid = elem(Enum.at(pids, 1),1)
    sender_public_key = GenServer.call(sender_pid, {:fetch_public})
    sender_private_key = GenServer.call(sender_pid, {:fetch_priv})
    receiver_public_key = GenServer.call(receiver_pid, {:fetch_public})
    transaction = [sender_public_key, receiver_public_key, :rand.uniform(4)]
    signature = sign(transaction, sender_private_key)
    IO.puts "Transaction initialized"
    if verifyTransaction(sender_pid, transaction, signature, node_list) do
      IO.puts "Transaction is valid"
      block = createBlock(transaction, sender_pid, miner_public_key, node_list)
      block
    else
      IO.puts "Transaction is invalid"
      transact(node_list, miner_pid)
    end
  end

  # This functions verifies whether a transaction is valid or not,
  # which means whether the sender has enough money to send. It also
  # checks whether the digital signature is valid or not.
  def verifyTransaction(pid, transaction, signature, node_list) do
    public_key = GenServer.call(pid, {:fetch_public})
    pid0 = elem(Enum.at(node_list,0), 1)
    current_ledger = GenServer.call(pid0, {:fetch_ledger})
    if verifySign(transaction, signature, public_key) do
      IO.puts "Signature is valid"
      transaction_amount = List.last(transaction)
      if received(pid) - sent(pid) >= transaction_amount do
        true
      else
        false
      end
    else
      IO.puts "Signature is invalid"
    end
  end

  # This functions calculates the total amount of money/coins sent
  # by a user/node.
  def sent(pid) do
    current_ledger = GenServer.call(pid, {:fetch_ledger})
    public_key = GenServer.call(pid, {:fetch_public})
    sent = Enum.reduce(current_ledger, 0, fn(x), acc1 -> 
      transactions = elem(x, 2)
      sent_per_block = Enum.reduce(transactions, 0, fn(y),acc -> 
          if public_key == Enum.at(y, 0) do
            acc = acc + Enum.at(y, 2)
          else
            acc = acc
          end
      end)
    acc1 = acc1 + sent_per_block
    end)
  end

  # This functions calculates the total amount of money/coins received
  # by a user/node.
  def received(pid) do
    current_ledger = GenServer.call(pid, {:fetch_ledger})
    public_key = GenServer.call(pid, {:fetch_public})
    received = Enum.reduce(current_ledger, 0, fn(x), acc1 -> 
      transactions = elem(x, 2)
      received_per_block = Enum.reduce(transactions, 0, fn(y), acc -> 
          if public_key == Enum.at(y, 1) do
            acc = acc + Enum.at(y, 2)
          else 
            acc = acc
          end

      end)
    acc1 = acc1 + received_per_block
    end)
  end

  # This functions digitally signs a message/transaction with
  # the private key.
  def sign(msg, private_key) do
    signed_data = :crypto.sign(:ecdsa, :sha256, hashify(msg), [private_key, :secp256k1])  
  end

  # This function verifies the digital signature.
  def verifySign(msg, signature, public_key) do
    :crypto.verify(:ecdsa, :sha256, hashify(msg), signature,[public_key, :secp256k1])
  end

  # This function creates a hash of data using the crypto module.
  # We are using sha256 as the digest.
  def hashify(thing_to_be_hashed) do
    hashed = :crypto.hash(:sha256, thing_to_be_hashed) |> Base.encode16
  end 
  
  # This function takes the no of miners from the users and starts
  # mining.
  def miningTest(node_list, no_of_miners) do
    miners = Enum.take_random(node_list, no_of_miners)
    Enum.map(miners, fn(x) -> 
      pid = elem(x,1)
      block = transact(node_list, pid)
      private_key = GenServer.call(pid, {:fetch_priv})
      public_key = GenServer.call(pid, {:fetch_public})
      GenServer.cast(pid, {:mine, node_list, private_key, public_key, block})
    end)
  end

end


defmodule PrivateKey do
@moduledoc """
This module generates private and public key 
pairs.
"""
  def generate do
    private_key = :crypto.strong_rand_bytes(32)

  end

  def to_public_key(private_key) do
    :crypto.generate_key(:ecdh, :crypto.ec_curve(:secp256k1), private_key)
    |> elem(0)
  end

  def to_public_hash(private_key) do
    private_key
    |> to_public_key
    |> hash(:sha256)
    |> hash(:ripemd160)
  end

  def to_public_address(private_key, version \\ <<0x00>>) do
    private_key
    |> to_public_hash
    |> Base58Check.encode(version)
  end
  
  defp hash(data, algorithm), do: :crypto.hash(algorithm, data)

end


defmodule ProofofWork do
@moduledoc """
This module implements functions for the proof of work 
protocol.
""" 
  def randomizer(length, type \\ :all) do
    alphabets = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    numbers = "0123456789"

    lists =
      cond do
        type == :alpha -> alphabets <> String.downcase(alphabets)
        type == :numeric -> numbers
        type == :upcase -> alphabets
        type == :downcase -> String.downcase(alphabets)
        true -> alphabets <> String.downcase(alphabets) <> numbers
      end
      |> String.split("", trim: true)

    do_randomizer(length, lists)
  end

  defp do_randomizer(length, lists) do
    get_range(length)
    |> Enum.reduce([], fn(_, acc) -> [Enum.random(lists) | acc] end)
    |> Enum.join("")
  end

  defp get_range(length) when length > 1, do: (1..length)
  defp get_range(length), do: [1]

  def generation(challenge) do
    answer = randomizer(25)
    attempt = challenge <> answer
    solution = :crypto.hash(:sha256, attempt) |> Base.encode16
    if String.starts_with?(solution, "00") do 
      IO.inspect self, label: "answer found #{answer} by pid"
      answer
    else
      generation(challenge)
    end
  end
end
