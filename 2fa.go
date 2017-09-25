package main

// 2fa = two factor authentication service

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"         //REST Framework
	"github.com/go-redis/redis"        //redis cache client
	"github.com/ttacon/libphonenumber" //Googles phone number management library
)

// We chose from these letters, based on the token type we have to generate
const capletters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const smalletters = "abcdefghijklmnopqrstuvwxyz"
const nums = "0123456789"
const symbols = "!@#$%^&*()-_=+,.?/:;{}[]`~"

type Result struct { //this is how the token looks like
	Token  string    `json:"token"`
	Expiry time.Time `json:"expiry"`
}

// structs for SMS4A API - a little complicated because it allows several messages in a call and several recipients per message
type Recipients struct {
	Dst string `json:"dst"`
}

type Messages struct {
	Text        string       `json:"text"`
	Rrecipients []Recipients `json:"recipients"`
}
type SMS4amsg struct {
	Mmessages []Messages `json:"messages"`
}

func main() {

	/* usage:
	http://localhost:8080/send/?dest=017615528046
	http://localhost:8080/token/&type="string"&length=8&exp=5

	supported types: string, lstring, ustring, numbers, symbol
	exp: expiry in minutes
	length: default 5 - max 25

	*/

	log.Println(time.Now(), "2fa started")
	RClient := initcache() //Redis.Client
	router := gin.Default()

	// router.GET("/token", maketoken)  //token generator
	//router.GET("/cachetest", initcache) //play with redis
	router.GET("/send", sendmessage) //send token via SMS4A
	router.Run()
}

func sendmessage(dest *gin.Context) {
	// Sends a Text message via retarus SMS for Applications REST API V1
	//SMS4A Credentials
	url := "https://sms4a.retarus.com/rest/v1/"
	rUser := "bernhard.hecker@retarus.de"
	rPwd := ".Retarus1"
	data := []byte(rUser + ":" + rPwd)
	rCred := base64.StdEncoding.EncodeToString(data) //encoded credentials
	fmt.Println(rCred)

	//generating token:

	token := maketoken("5", "5", "numbers")

	//Query Parameter and Number Handling
	destnum, _ := dest.GetQuery("dest") //destination number

	destnumvalid, err := libphonenumber.Parse(destnum, "DE") //validate phone number
	if err != nil {
		log.Println(time.Now(), err)
	}

	// formattedNum := libphonenumber.Format(destnumvalid, libphonenumber.INTERNATIONAL)

	i := libphonenumber.GetNumberType(destnumvalid)

	if i != libphonenumber.MOBILE {
		log.Println(time.Now(), "Not Mobile Number: ", destnumvalid)
	}

	//here we should either have a valid mobile number or leave the show...

	//is retarus online?
	status, err := http.Get(url + "version")
	if err != nil {
		log.Println(time.Now(), err)
	}
	defer status.Body.Close()

	if status.StatusCode != 200 {
		log.Fatalln(time.Now(), "SMS Rest API Error, Status code: ", status.StatusCode)
	}
	// dest.String(200, "%v", status)

	// Building SMS Message
	arecipient := []Recipients{{destnum}}
	amessages := []Messages{{"Ich kann SMS per API schicken...", arecipient}} //this is the SMS Json Object
	asms := SMS4amsg{amessages}
	fmt.Println("arecipient:", arecipient)
	fmt.Println("amessages:", amessages)
	fmt.Println("sms:", asms)

	//http post message
	// first we build the request
	jsonStr, errs := json.Marshal(asms)
	if errs != nil {
		log.Println(time.Now(), errs)
	}

	req, err := http.NewRequest("POST", url+"jobs", bytes.NewBuffer(jsonStr))
	fmt.Println(req)

	if err != nil {
		log.Println(time.Now(), err)
	}
	req.SetBasicAuth(rUser, rPwd) //we're precise and set all neccessary headers, just in case
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("charset", "utf-8")
	defer req.Body.Close()

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		log.Println(time.Now(), err)
	}

	//http response...
	defer req.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	bd := string(body[:])
	log.Println(time.Now(), "JobID: ", bd)

	if err != nil {
		log.Println(time.Now(), err)
	}

}

func maketoken(qlen string, qexp string, qtype string) struct {

	/*qlen, _ := q.GetQuery("length") //how long should it be
	qtype, _ := q.GetQuery("type")  //what kind of token do we want to have?
	qexp, _ := q.GetQuery("exp")    //how many minutes does it live?
	*/

	//defaults
	dqtype := smalletters
	dlength := 5
	dexp := 5

	qex, err := time.ParseDuration(qexp)
	if err != nil {
		log.Println(time.Now(), err)
	}
	
	if qex == 0 {
		qex = time.Duration(dexp) * time.Minute //default 5 minutes
	}

	var LetterBytes string

	switch qtype {
	case "string":
		LetterBytes = capletters + smalletters
	case "lstring":
		LetterBytes = smalletters
	case "ustring":
		LetterBytes = capletters
	case "numbers":
		LetterBytes = nums
	case "symbol":
		LetterBytes = symbols + smalletters + capletters
	default:
		LetterBytes = dqtype // if something goes wrong, we just generate a token instead of throwing an error
		log.Println(time.Now(), "Incorrect type query parameter: ", qtype)
	}

	tokenlength, err := strconv.Atoi(qlen)
	if err != nil {
		log.Println(time.Now(), "Incorrect length query parameter: ", err)
	}

	if tokenlength > 25 { //max 25
		tokenlength = 25
	}

	if tokenlength < 1 { // just in case: set to default
		tokenlength = dlength
	}

	//tests
	fmt.Println("len: ", tokenlength)
	fmt.Println("type: ", qtype)
	fmt.Println("LetterBytes", LetterBytes)
	fmt.Println("lifespan: ", qex)

	var ergebnis Result
	// ergebnis = make([]Result, 10)

	b := make([]byte, tokenlength)
	for i := range b {
		b[i] = LetterBytes[rand.Intn(len(LetterBytes))]

	}
	str := string(b[:])
	exp := time.Now().Add(qex)
	ergebnis = Result{str, exp}

	// q.IndentedJSON(200, ergebnis)

	return ergebnis
}

func storekey(key string) {
	//Todo store a key in the cache

}

func initcache() redis.Client {

	//todo initialize cache
	// Host ret2fa.redis.cache.windows.net
	client := redis.NewClient(&redis.Options{
		Addr:     "ret2fa.redis.cache.windows.net:6379",
		Password: "LvwurUoZrmSbozrEINuztX7PsLTI0ZUFw05gz8UoeGs=", // Password
		DB:       0,                                              // use default DB
	})

	pong, err := client.Ping().Result()
	fmt.Println(pong, err)

	Client := *client

	return Client
	/*
		err = client.Set("key", urrrl, 0).Err()
		if err != nil {
			panic(err)
		}

		val, err := client.Get("key").Result()
		if err != nil {
			panic(err)
		}
		fmt.Println("key", val)

		val2, err := client.Get("key2").Result()
		if err == redis.Nil {
			fmt.Println("key2 does not exists")
		} else if err != nil {
			panic(err)
		} else {
			fmt.Println("key2", val2)
		}
	*/
}

//func getkey (token string) keyexists {
//TODO find key and return bool
//}
