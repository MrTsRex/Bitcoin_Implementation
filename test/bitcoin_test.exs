defmodule BitTest do
  use ExUnit.Case


  test "SHA256 hashing" do
    thing = "kchdcekfhedcfefe23rddcf"
    assert Main.hashify(thing)
  end

 test "public key generation" do
    private_key = "vfdsjkclkocfjcnmkslcijd"
    assert PrivateKey.to_public_key(private_key)
 end

 test "private key generation" do
   assert PrivateKey.generate
 end

  test "generating nonce" do
    assert ProofofWork.randomizer(25)
  end

  test "proof of work" do
    assert ProofofWork.generation("fdnsjdkieroikjr45n3wosdf")
  end

  test "generating the digital signature with private key" do
    private_key = PrivateKey.generate
    public_key = PrivateKey.to_public_key(private_key)
    signature = Main.sign("Joshi", private_key)
    assert signature
  end

  test "Verifying the digital signature with public key" do
    private_key = PrivateKey.generate
    public_key = PrivateKey.to_public_key(private_key)
    signature = Main.sign("Joshi", private_key)
    assert Main.verifySign("Joshi", signature, public_key)
  end

  test "creating nodes" do
    assert Main.createNodes(2)
  end

  test "creating wallet" do
    node_list = Main.createNodes(2)

    assert Main.createWallet(node_list)
  end

  test "Intializing transactions " do
    node_list = Main.createNodes(2)
    Main.createWallet(node_list)
    assert Main.createGenesisBlock(node_list)
  end

  test "displaying ledger" do
    node_list = Main.createNodes(2)
    process = Enum.take_random(node_list, 1)
    pid = elem(Enum.at(process, 0),1)
    Main.createWallet(node_list)
    Main.createGenesisBlock(node_list)
    assert Main.displayLedger(pid)
  end

  test "creating block for transactions" do
    node_list = Main.createNodes(2)
    process = Enum.take_random(node_list, 1)
    pid = elem(Enum.at(process, 0),1)
    sender_private_key = PrivateKey.generate
    receiver_private_key = PrivateKey.generate
    miner_private_key = PrivateKey.generate
    miner_public_key = PrivateKey.to_public_key(miner_private_key)
    Main.createWallet(node_list)
    Main.createGenesisBlock(node_list)
    Main.displayLedger(pid)
    transaction =[sender_private_key, receiver_private_key, :rand.uniform(4)]
    assert Main.createBlock(transaction, pid, miner_public_key)
  end

  test "verifying proof of work" do
    node_list = Main.createNodes(2)
    process = Enum.take_random(node_list, 1)
    miner_pid = elem(Enum.at(process, 0),1)
    sender_private_key = PrivateKey.generate
    receiver_private_key = PrivateKey.generate
    miner_private_key = PrivateKey.generate
    miner_public_key = PrivateKey.to_public_key(miner_private_key)
    Main.createWallet(node_list)
    Main.createGenesisBlock(node_list)
    Main.displayLedger(miner_pid)
    transaction =[sender_private_key, receiver_private_key, :rand.uniform(4)]
    block = Main.createBlock(transaction, miner_pid, miner_public_key)
    transactions = elem(block, 1)
    nonce = ProofofWork.generation(transactions)
    assert Main.verifyProofOfWork(block, nonce, miner_pid) == true
  end

  test "caluclating the amount of bitcoins sent by particular user" do
    node_list = Main.createNodes(2)
    process = Enum.take_random(node_list, 1)
    pid = elem(Enum.at(process, 0),1)
    Main.createWallet(node_list)
    Main.createGenesisBlock(node_list)
    Main.displayLedger(pid)
    assert Main.sent(pid)
  end

  test "caluclating the amount of bitcoins received by particular user" do
    node_list = Main.createNodes(2)
    process = Enum.take_random(node_list, 1)
    pid = elem(Enum.at(process, 0),1)
    Main.createWallet(node_list)
    Main.createGenesisBlock(node_list)
    Main.displayLedger(pid)
    assert Main.received(pid)
  end

  test "verify whether the user has enough money to do transaction" do
    node_list = Main.createNodes(2)
    process = Enum.take_random(node_list, 1)
    pid = elem(Enum.at(process, 0),1)
    Main.createWallet(node_list)
    Main.createGenesisBlock(node_list)
    Main.displayLedger(pid)
    assert Main.sent(pid)
    assert Main.received(pid)
    Main.createWallet(node_list)
    Main.createGenesisBlock(node_list)
    Main.displayLedger(pid)
    miner_private_key = PrivateKey.generate
    miner_public_key = PrivateKey.to_public_key(miner_private_key)
    sender_private_key = PrivateKey.generate
    receiver_private_key = PrivateKey.generate
    transaction =[sender_private_key, receiver_private_key, :rand.uniform(4)]
    block = Main.createBlock(transaction, pid, miner_public_key)
    signature = Main.sign(transaction, sender_private_key)
    assert Main.verifyTransaction(pid, transaction, signature)
  end

  test "generating random transactions" do
    node_list = Main.createNodes(2)
    process = Enum.take_random(node_list, 1)
    pid = elem(Enum.at(process, 0),1)
    Main.createWallet(node_list)
    Main.createGenesisBlock(node_list)
    assert Main.transact(node_list, pid)
  end

  test "mining" do
    node_list = Main.createNodes(2)
    process = Enum.take_random(node_list, 1)
    pid = elem(Enum.at(process, 0),1)
    Main.createWallet(node_list)
    Main.createGenesisBlock(node_list)
    Main.transact(node_list, pid)
    Main.miningTest(node_list, 5)
  end
end
