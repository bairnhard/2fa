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

	"github.com/ttacon/libphonenumber"

	"github.com/gin-gonic/gin"
)

// const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const capletters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const smalletters = "abcdefghijklmnopqrstuvwxyz"
const nums = "0123456789"
const symbols = "!@#$%^&*()-_=+,.?/:;{}[]`~"

type Result struct { //this is how the token looks like
	Token  string    `json:"token"`
	Expiry time.Time `json:"expiry"`
}

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

	log.Println(time.Now(), "2fa started")

	router := gin.Default()

	router.GET("/token", maketoken) //token generator

	router.GET("/send", sendmessage) //send token via SMS4A

	router.Run()
}

func sendmessage(dest *gin.Context) {

	//SMS4A Credentials
	url := "https://sms4a.retarus.com/rest/v1/"
	rUser := "bernhard.hecker@retarus.de"
	rPwd := ".Retarus1"
	data := []byte(rUser + ":" + rPwd)
	rCred := base64.StdEncoding.EncodeToString(data) //encoded credentials
	fmt.Println(rCred)

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

func maketoken(q *gin.Context) {

	qlen, _ := q.GetQuery("length") //how long should it be
	qtype, _ := q.GetQuery("type")  //what kind of token do we want to have?
	qexp, _ := q.GetQuery("exp")    //how many minutes does it live?

	qex, _ := time.ParseDuration(qexp)
	if qexp == "" {
		qex = 5 * time.Minute
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
	}

	tokenlength, err := strconv.Atoi(qlen)
	if err != nil {
		log.Println(time.Now(), "Incorrect length query parameter: ", err)
	}

	//tests
	fmt.Println("len: ", tokenlength)
	fmt.Println("type: ", qtype)
	fmt.Println("LetterBytes", LetterBytes)
	fmt.Println("lifespan: ", qex)
	// const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	var ergebnis Result
	// ergebnis = make([]Result, 10)

	// for loop := 0; loop < 10; loop++ {

	b := make([]byte, tokenlength)
	for i := range b {
		b[i] = LetterBytes[rand.Intn(len(LetterBytes))]

	}
	str := string(b[:])
	exp := time.Now().Add(qex)
	ergebnis = Result{str, exp}

	//}
	q.IndentedJSON(200, ergebnis)
}
