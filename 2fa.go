package main

// 2fa = two factor authentication service
// Author: Bernhard Hecker

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"  //REST Framework
	"github.com/go-redis/redis" //redis cache client
	//Googles phone number management library
	"github.com/nyaruka/phonenumbers" //newer rewrite of lobphonenumber
	"gopkg.in/yaml.v2"                //YAML Parser for external configuration
)

// We chose from these letters, based on the token type we have to generate
const capletters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const smalletters = "abcdefghijklmnopqrstuvwxyz"
const nums = "0123456789"
const symbols = "!@#$%^&*()-_=+,.?/:;{}[]`~"

type Conf struct { //This stores the config
	Rhost              string        `yaml:"rhost"` //redis host
	Rpass              string        `yaml:"rpass"` //redis password
	Suser              string        `yaml:"suser"` //SMS User
	Spass              string        `yaml:"spass"` //SMS Password
	DefaultTokenLength int           `yaml:"detaulttokenlength"`
	DefaulTokentExpiry time.Duration `yaml:"defaultokentexpiry"`
	MaxTokenLength     int           `yaml:"maxtokenlength"`
	Messageprefix      string        `yaml:"messageprefix"`
	Messagesuffix      string        `yaml:"messagesuffix"`
	HTTPPort           string        `yaml:"httpport"`
}

type Result struct { //this is how the token looks like
	Token  string        `json:"token"`
	Expiry time.Duration `json:"expiry"`
}

type Jobid struct { //retarus SMS jobid
	JobId string
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

type Postmsg struct {
	Length  string `json:"length" binding:"required"`
	Expiry  string `json:"exp" binding:"required"`
	Destnum string `json:"destnum" binding:"required"`
	Type    string `json:"type" binding:"required"`
	Msg     string `json:"msg" binding:"required"`
}

var RClient redis.Client
var Cfg Conf

func main() {

	/* usage:
	http://localhost:8080/send/?dest=017615528046&type="string"&length=8&exp=5

	http://localhost:8080/token/&type="string"&length=8&exp=5

	supported types: string, lstring, ustring, numbers, symbol
	exp: expiry in time.Duration
	length: token length
	msg: message !TOKEN! will be replaced by token

	*/

	log.Println(time.Now(), "2fa started")
	readconfig()

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt)

	go func() {
		select {
		case sig := <-c:
			fmt.Printf("Got %s signal. Aborting...\n", sig)
			os.Exit(1)
		}
	}()

	//several things need to be initialized here...
	RClient = initcache()            //Redis.Client
	rand.Seed(time.Now().UnixNano()) //make random random
	router := gin.Default()

	router.LoadHTMLFiles("HTMLPage1.html")
	router.GET("/", usage)
	// router.GET("/send", sendmessage) //send token via SMS4A
	router.GET("/check", checktoken) //validate token
	router.POST("/tokens", tokens)

	router.Run(":" + Cfg.HTTPPort)
}

func tokens(c *gin.Context) {
	var Message Postmsg //this is the json we get posted
	err := c.BindJSON(&Message)
	if err != nil {
		log.Println(time.Now(), err)
		c.JSON(500, "MSG Error")
		return
	}
	var job Jobid
	job = sendmessage(Message)
	c.JSON(200, job)

}

func usage(c *gin.Context) {

	c.HTML(http.StatusOK, "HTMLPage1.html", nil)

}

func readconfig() {

	//config File Handling
	confFile, err := ioutil.ReadFile("2fa.cfg")
	if err != nil {
		log.Println(err)
	}

	err = yaml.Unmarshal(confFile, &Cfg)
	if err != nil {
		log.Println(time.Now(), "yaml error: ", err)
	}
}

func sendmessage(Message Postmsg) Jobid {
	// Sends a Text message via retarus SMS for Applications REST API V1
	//SMS4A Credentials
	url := "https://sms4a.retarus.com/rest/v1/"
	rUser := Cfg.Suser
	rPwd := Cfg.Spass

	//generating token:
	token := maketoken(Message)

	//Query Parameter and Number Handling
	destnum := Message.Destnum
	//destnum, _ := dest.GetQuery("dest")                    //destination number
	destnumvalid, err := phonenumbers.Parse(destnum, "DE") //validate phone number
	if err != nil {
		log.Println(time.Now(), err)
	}

	i := phonenumbers.GetNumberType(destnumvalid)
	if i != phonenumbers.MOBILE && i != phonenumbers.FIXED_LINE_OR_MOBILE { //either mobile or somewhat unknown
		log.Println(time.Now(), "Not Mobile Number: ", destnumvalid)
		//Message.IndentedJSON(500, "Not mobile number")
		var r Jobid
		r.JobId = "Not mobile Number"
		return r //here we should either have a valid mobile number or leave the show...
	}

	// Building SMS Message
	msgstring := Message.Msg
	//msgstring, _ := dest.GetQuery("msg")
	if msgstring == "" {
		msgstring = Cfg.Messageprefix + "!TOKEN!" + Cfg.Messagesuffix
	}

	msgs := strings.Split(msgstring, "!TOKEN!")
	msgstring = msgs[0] + token.Token + " " + msgs[1]

	arecipient := []Recipients{{destnum}}
	amessages := []Messages{{msgstring, arecipient}}
	asms := SMS4amsg{amessages}

	//http post message
	// first we build the request
	jsonStr, errs := json.Marshal(asms)
	if errs != nil {
		log.Println(time.Now(), errs)
	}

	req, err := http.NewRequest("POST", url+"jobs", bytes.NewBuffer(jsonStr))
	//fmt.Println(req)
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
	//defer req.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(time.Now(), err)
	}

	bd := string(body[:])
	log.Println(time.Now(), "JobID: ", bd)
	log.Println(time.Now(), "Body: ", body)

	var bdj Jobid

	errr := json.Unmarshal(body, &bdj)
	if errr != nil {
		log.Println(time.Now(), errr)
	}
	//fmt.Println(" BDJ.Jobid: ", bdj.JobId)

	storetoken(token, bdj.JobId, RClient)
	return bdj
	//dest.IndentedJSON(200, bdj)

}

func maketoken(Message Postmsg) Result { //generates token
	//qlen, _ := q.GetQuery("length") //how long should it be
	qlen := Message.Length
	//qtype, _ := q.GetQuery("type")  //what kind of token do we want to have?
	qtype := Message.Type
	//qexp, _ := q.GetQuery("exp")    //how many minutes does it live?
	qexp := Message.Expiry

	//defaults
	dqtype := smalletters
	dlength := Cfg.DefaultTokenLength // Config Parameter
	dexp := Cfg.DefaulTokentExpiry

	qex, err := time.ParseDuration(qexp)

	if err != nil {
		log.Println(time.Now(), err)
	}

	if qex == 0 {
		qex = time.Duration(dexp) * time.Minute // set default
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

	if tokenlength > Cfg.MaxTokenLength { //max 25
		tokenlength = Cfg.MaxTokenLength
	}

	if tokenlength < 1 { // just in case: set to default
		tokenlength = dlength
	}

	var ergebnis Result

	b := make([]byte, tokenlength)
	for i := range b {
		b[i] = LetterBytes[rand.Intn(len(LetterBytes))]
	}

	ergebnis = Result{string(b[:]), qex}

	return ergebnis
}

func initcache() redis.Client { //Initializes cache connection

	client := redis.NewClient(&redis.Options{
		Addr:     Cfg.Rhost,
		Password: Cfg.Rpass,
		DB:       0, // use default DB
	})

	log.Println(time.Now(), "redis connection established")

	Client := *client

	return Client

}

func storetoken(token Result, key string, RClient redis.Client) { //stores token and key in redis

	err := RClient.Set(key, hash(token.Token), token.Expiry).Err()
	if err != nil {
		log.Println(time.Now(), "redis store error: ", err)
	}

}

func checktoken(req *gin.Context) {

	token, _ := req.GetQuery("token")
	hval := hash(token)
	//fmt.Println(hval)

	key, _ := req.GetQuery("id")

	val, err := RClient.Get(key).Result()
	if err != nil {
		log.Println(err)
	}
	fmt.Println(key, val)

	if val == string(hval[:]) {
		req.IndentedJSON(200, "true")
	} else {
		req.IndentedJSON(200, "false")
	}

}

func hash(key string) []byte {
	h := sha256.New()
	h.Write([]byte(key))
	return h.Sum(nil)
}
