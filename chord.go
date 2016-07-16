package main

import (
	"bufio"
	"crypto/sha1"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"net/rpc"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"log"
)

const maxSuccessors = 3

func getLocalAddress() string {
	var localaddress string

	ifaces, err := net.Interfaces()
	if err != nil {
		panic("init: failed to find network interfaces")
	}

	// find the first non-loopback interface with an IP address
	for _, elt := range ifaces {
		if elt.Flags&net.FlagLoopback == 0 && elt.Flags&net.FlagUp != 0 {
			addrs, err := elt.Addrs()
			if err != nil {
				panic("init: failed to get addresses for network interface")
			}

			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok {
					if ip4 := ipnet.IP.To4(); len(ip4) == net.IPv4len {
						localaddress = ip4.String()
						break
					}
				}
			}
		}
	}
	if localaddress == "" {
		panic("init: failed to find non-loopback interface with valid address on this node")
	}

	return localaddress
}

func hashString(elt string) *big.Int {
	hasher := sha1.New()
	hasher.Write([]byte(elt))
	return new(big.Int).SetBytes(hasher.Sum(nil))
}

//used to take the entry from the finger table, to find what its going to hash to on the ring
const keySize = sha1.Size * 8

var hashMod = new(big.Int).Exp(big.NewInt(2), big.NewInt(keySize), nil)

func (n *Node) jump(fingerentry int) *big.Int {
	elt := hashString(n.mAddress)
	two := big.NewInt(2)
	fingerentryminus1 := big.NewInt(int64(fingerentry) - 1)
	jump := new(big.Int).Exp(two, fingerentryminus1, nil)
	sum := new(big.Int).Add(elt, jump)

	return new(big.Int).Mod(sum, hashMod)
}

// Node is the main struct
type Node struct {
	mAddress     string
	mSuccessors  []string
	mPredecessor string
	mFingers     []string
	mNext        int

	mutex   sync.Mutex
	mBucket map[string]string
}

// Nothing is literally nothing
type Nothing struct{}

// FindReturn is the return of the find
type FindReturn struct {
	Address string
	Found   bool
}

func (n *Node) dumpFinger() {
	fmt.Print("Finger Table:")
	for i := 0; i < len(n.mFingers); i++ {
		fmt.Println(strconv.Itoa(i) + ": " + n.mFingers[i])
	}
}

// Dump is a way to call dump on another node
func (n *Node) dump() {
	fmt.Print("Bucket: ")
	fmt.Print(n.mBucket)
	fmt.Println("")
	fmt.Print("Address: ")
	fmt.Println(n.mAddress)
	fmt.Print("Successors: ")
	fmt.Println(n.mSuccessors)
	fmt.Print("Predecessor: ")
	fmt.Println(n.mPredecessor)
	// fmt.Print("Successor Hash: ")
	// fmt.Print("\t")
	// fmt.Println(hashString(n.mSuccessors[0]))
	// fmt.Print("My Hash: ")
	// fmt.Print("\t")
	// fmt.Print("\t")
	// fmt.Println(hashString(n.mAddress))
	// fmt.Print("Predeccessor Hash: ")
	// fmt.Print("\t")
	// fmt.Println(hashString(n.mPredecessor))
	// fmt.Println("0 should be:", n.find(n.jump(0)))
	// fmt.Println("159 should be:", n.find(n.jump(159)))

	fmt.Print("Finger Table:")
	last := ""
	for i := 0; i < len(n.mFingers); i++ {
		if n.mFingers[i] != last {
			fmt.Println(strconv.Itoa(i) + ": " + n.mFingers[i])
		}
		last = n.mFingers[i]
	}
}

// Dump is a way to call dump on another node
func (n *Node) Dump(junk *Nothing, nothing *Nothing) error {
	n.dump()
	return nil
}

func (n *Node) dumpKey(key string) {
	junk := new(Nothing)
	successor := n.find(hashString(key))
	call(successor, "Dump", &junk, &junk)
}

func (n *Node) dumpAddr(address string) {
	junk := new(Nothing)
	call(address, "Dump", &junk, &junk)
}

func call(address string, method string, request interface{}, reply interface{}) error {
	client, err := rpc.DialHTTP("tcp", address)
	if err != nil {
		return fmt.Errorf("\t The Method %s had an error connecting to node %s: %v", method, address, err)
	}
	defer client.Close()
	return client.Call("Node."+method, request, reply)
}

func between(start, elt, end *big.Int, inclusive bool) bool {
	if end.Cmp(start) > 0 {
		return (start.Cmp(elt) < 0 && elt.Cmp(end) < 0) || (inclusive && elt.Cmp(end) == 0)
	}
	return start.Cmp(elt) < 0 || elt.Cmp(end) < 0 || (inclusive && elt.Cmp(end) == 0)
}

// GetSuccessor returns the nodes successor
func (n *Node) GetSuccessor(junk *Nothing, address *string) error {
	*address = n.mSuccessors[0]
	return nil
}

// GetSuccessorList returns the successorList
func (n *Node) GetSuccessorList(junk *Nothing, successors *[]string) error {
	*successors = n.mSuccessors
	return nil
}

// Put puts the request in the node it is called on
func (n *Node) Put(request *[]string, junk *Nothing) error {
	keyValue := *request
	n.mBucket[keyValue[0]] = keyValue[1]
	return nil
}

// Get gets the value at the posistion key from the bucket of the called node
func (n *Node) Get(key *string, value *string) error {
	*value = n.mBucket[*key]
	return nil
}

// Delete deletes the key and the value from the bucket of the called node
func (n *Node) Delete(key *string, junk *Nothing) error {
	delete(n.mBucket, *key)
	return nil
}

// Join joins the ring
func (n *Node) Join(address *string, successor *string) error {
	*successor = n.find(hashString(*address))
	call(*successor, "GetAll", address, &n.mBucket)
	return nil
}

// GetPred returns the predecessor of the node it is called on
func (n *Node) GetPredecessor(junk *Nothing, address *string) error {
	*address = n.mPredecessor
	return nil
}

func (n *Node) stabilize() error {
	junk := new(Nothing)
	var successors []string
	err := call(n.mSuccessors[0], "GetSuccessorList", &junk, &successors)
	if err == nil {
		n.mSuccessors[1] = successors[0]
		n.mSuccessors[2] = successors[1]
	} else {
		log.Printf("\tOur successor '%s' failed", n.mSuccessors[0])
		if n.mSuccessors[0] == "" {
			log.Printf("\tSetting successor to ourself")
			n.mSuccessors[0] = n.mAddress
		} else {
			log.Printf("\tSetting '%s' as our new successor ", n.mSuccessors[1])
			n.mSuccessors[0] = n.mSuccessors[1]
			n.mSuccessors[1] = n.mSuccessors[2]
			n.mSuccessors[2] = ""
		}
	}

	x := ""
	call(n.mSuccessors[0], "GetPredecessor", &junk, &x)
	if between(hashString(n.mAddress),hashString(x),hashString(n.mSuccessors[0]),false) && x != "" {
		log.Printf("\tSetting successor to '%s'", x)
		n.mSuccessors[0] = x
	}

	err = call(n.mSuccessors[0], "Notify", n.mAddress, &junk)
	if err != nil {
	}
	return nil
}

func (n *Node) checkPredecessor() error {
	if n.mPredecessor != "" {
		client, err := rpc.DialHTTP("tcp", n.mPredecessor)
		if err != nil {
			log.Printf("\t Our predecessor '%s' has failed", n.mPredecessor)
			n.mPredecessor = ""
		} else {
			client.Close()
		}
	}
	return nil
}

func (n *Node) fixFingers() error{
	n.mNext++
	if n.mNext > len(n.mFingers)-1 {
		n.mNext = 0
	}
	addrs := n.find(n.jump(n.mNext))

	if n.mFingers[n.mNext] != addrs && addrs != "" {
		log.Printf("\tWriting FingerTable entry '%d' as '%s'\n", n.mNext, addrs)
		n.mFingers[n.mNext] = addrs
	}
	for {
		n.mNext++
		if n.mNext > len(n.mFingers)-1 {
			n.mNext = 0
			return nil
		}

		if between(hashString(n.mAddress), n.jump(n.mNext), hashString(addrs), false) && addrs != "" {
			n.mFingers[n.mNext] = addrs
		} else {
			n.mNext--
			return nil
		}
	}
}

func (n *Node) find(id *big.Int) string {
	findreturn := FindReturn{n.mSuccessors[0], false}
	count := 32
	for !findreturn.Found {
		if count > 0 {
			err := call(findreturn.Address, "FindSuccessor",id, &findreturn)
			if err == nil {
				count--
			} else {
				count = 0
			}
		} else {
			return ""
		}
	}
	return findreturn.Address
}

func (n *Node) FindSuccessor(id *big.Int, findreturn *FindReturn) error {
	if between(hashString(n.mAddress), id, hashString(n.mSuccessors[0]), true) {
			findreturn.Address = n.mSuccessors[0]
			findreturn.Found = true
			return nil
		}
		findreturn.Address = n.closestPrecedingNode(id)
		return nil
}

func (n *Node) closestPrecedingNode(id *big.Int) string {
	for i := len(n.mFingers) - 1; i > 0; i-- {
			if between(hashString(n.mAddress), hashString(n.mFingers[i]), id, false) {
				return n.mFingers[i]
			}
		}
		return n.mSuccessors[0]
}

// Notify is called from a node, that thinks it might be our successor
func (n *Node) Notify(address string, junk *Nothing) error {
	if n.mPredecessor == "" ||
			between(hashString(n.mPredecessor),hashString(address),hashString(n.mAddress),false) {
			n.mPredecessor = address
		}
		return nil
}

//PutAll is used to give our bucket to our successor, if we are going to quit
func (n *Node) PutAll(bucket map[string]string, junk *Nothing) error {
	for key, value := range bucket {
			n.mBucket[key] = value
		}
		return nil
}

//GetAll is used to get all of the stuff that should be in our bucket when we join
func (n *Node) GetAll(address string, junk *Nothing) error {
	tempBucket := make(map[string]string)
	for key, value := range n.mBucket {
		if between(hashString(n.mPredecessor), hashString(string(key)), hashString(address), false) {
			tempBucket[key] = value
			delete(n.mBucket, key)
		}
	}
	call(address, "PutAll", tempBucket, junk)
	return nil
}

func main() {
	port := ":3410"
	hasSetPort := false
	hasCreated := false
	hasJoined := false
	junk := new(Nothing)
	reader := bufio.NewReader(os.Stdin)
	node := Node{
		mAddress:     getLocalAddress() + port,
		mSuccessors:  make([]string, maxSuccessors),
		mBucket:      make(map[string]string),
		mPredecessor: "",
		mFingers:     make([]string, 160),
		mNext:        0}
	go func() {
		for {
			time.Sleep(time.Second)
			if hasCreated || hasJoined {
				node.stabilize()
				node.checkPredecessor()
			}
		}
	}()
	go func() {
		for {
			time.Sleep(time.Second / 100)
			if hasCreated || hasJoined {
				node.fixFingers()
			}
		}
	}()
	for {
		text, _ := reader.ReadString('\n')
		words := strings.Fields(text)
		switch words[0] {
		case "":
			fmt.Println("")

		case "help":
			fmt.Println("commands: help, quit, port, create, join, dump, put, get, delete, putrandom")

		case "port":
			if len(words) == 1 {
				if hasSetPort {
					fmt.Println("The port is: " + port)
				} else {
					fmt.Println("Default Port is :3410")
				}
			} else {
				if !hasSetPort {
					port = words[1]
					if !strings.HasPrefix(port, ":") {
						port = ":" + port
					}
					fmt.Println("The port is", port)
					hasSetPort = true
					node.mAddress = node.mAddress[:len(node.mAddress)-5] + port
				}
			}

		case "create":
			if hasCreated {
				fmt.Println("The ring has already been created, this command does not work anymore")
			} else {
				go func() {
					rpc.Register(&node)
					rpc.HandleHTTP()
					err := http.ListenAndServe(port, nil)
					if err != nil {
						fmt.Println(err.Error())
					}
				}()

				node.mSuccessors[0] = node.mAddress
				node.mPredecessor = ""
				hasCreated = true
			}

		case "join":
			if hasJoined || hasCreated {
				fmt.Println("This node is already part of a ring")
			} else if len(words) != 2 {
				fmt.Println("Join takes only an address")
			} else {
				go func() {
					rpc.Register(&node)
					rpc.HandleHTTP()
					err := http.ListenAndServe(port, nil)
					if err != nil {
						fmt.Println(err.Error())
					}
				}()
				successor := ""
				call(words[1], "Join", node.mAddress, &successor)
				node.mSuccessors[0] = successor
				hasCreated = true
				hasJoined = true
			}

		case "quit":
			call(node.mSuccessors[0], "PutAll", node.mBucket, &junk)
			os.Exit(0)

		case "put":
			if !hasCreated {
				fmt.Println("The ring hasnt been created yet, this wont work")
			} else {
				if len(words) != 3 {
					fmt.Println("Put requires a Key, and a Value")
				} else {
					request := []string{words[1], words[2]}
					successor := node.find(hashString(words[1]))
					call(successor, "Put", &request, &junk)
				}
			}

		case "get":
			if !hasCreated {
				fmt.Println("The ring hasnt been created yet, this wont work")
			} else {
				if len(words) != 2 {
					fmt.Println("Put requires a Key")
				} else {
					response := ""
					successor := node.find(hashString(words[1]))
					call(successor, "Get", &words[1], &response)
					fmt.Println(response)
				}
			}
		case "delete":
			if !hasCreated {
				fmt.Println("The ring hasnt been created yet, this wont work")
			} else {
				if len(words) != 2 {
					fmt.Println("Put requires a Key")
				} else {
					successor := node.find(hashString(words[1]))
					call(successor, "Delete", &words[1], &junk)

				}
			}

		case "dump":
			node.dump()

		case "dumpkey":
			if len(words) != 2 {
				fmt.Println("dumpkey requires a Key")
			} else {
				node.dumpKey(words[1])
			}
		case "dumpaddr":
			if len(words) != 2 {
				fmt.Println("dumpaddr requires an address")
			} else {
				node.dumpKey(words[1])
			}
		case "dumpfinger":
			if len(words) != 1 {
				fmt.Println("dumpfinger doesnt take any arguements")
			} else {
				node.dumpFinger()
			}

		case "test":
			testCase := "144.38.195.37:3415"
			fmt.Println(testCase)
			fmt.Println(hashString(testCase))

			fmt.Println("The find returned:")
			fmt.Println(node.find(hashString(testCase)))

			// fmt.Println("the findhash returned:")
			// fmt.Println(node.findHash(hashString(testCase)))

		case "putrandom":
			if len(words) != 2 {
				fmt.Println("putrandom needs an amount")
			} else {
				letterList := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
				//r := rand.NewSource(time.Now().UnixNano())
				amount, _ := strconv.Atoi(words[1])
				for i := 0; i < amount; i++ {
					randKey := ""
					randValue := ""
					for j := 0; int32(j) < rand.Int31n(20); j++ {
						index := rand.Int31n(int32(len(letterList)))
						randValue += string(letterList[index])
					}
					for j := 0; int32(j) < rand.Int31n(20); j++ {
						index := rand.Int31n(int32(len(letterList)))
						randKey += string(letterList[index])
					}
					request := []string{randKey, randValue}
					successor := node.find(hashString(randKey))
					//fmt.Println(successor)
					call(successor, "Put", &request, &junk)

				}
			}
		default:
			fmt.Println("that was not a vaild command")
		}
	}
}
