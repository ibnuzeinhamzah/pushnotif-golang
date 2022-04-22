package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/messaging"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/robfig/cron"
	"google.golang.org/api/option"
)

var db *sql.DB
var minDistance float64
var dbuser string
var dbname string
var dbhost string
var dbpass string
var dbport string

func init() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	minDistance, _ = strconv.ParseFloat(os.Getenv("min_distance"), 64)
	dbuser, dbpass, dbname, dbhost, dbport =
		os.Getenv("DBUSER"),
		os.Getenv("DBPASSWORD"),
		os.Getenv("DBNAME"),
		os.Getenv("DBHOST"),
		os.Getenv("DBPORT")
}

type SpatialRef struct {
	Wkid       int `json:"wkid"`
	LatestWkid int `json:"latestWkid"`
}

type SampleLocation struct {
	X                float64 `json:"x"`
	Y                float64 `json:"y"`
	SpatialReference SpatialRef
}

type Sample struct {
	LocationId int            `json:"locationid"`
	RasterId   int            `json:"rasterId"`
	Resolution int            `json:"resolution"`
	Value      string         `json:"value"`
	Location   SampleLocation `json:"location"`
}

type ListSample struct {
	Samples []Sample `json:"samples"`
}

type PolygonDB struct {
	Severity string `json:"severity"`
	Polygon  string `json:"polygons"`
}

type ListPolygonDB struct {
	ListPolygonDB []PolygonDB `json:"polygons"`
}

type UserToken struct {
	Token string  `json:"token"`
	Lat   float64 `json:"lat"`
	Lon   float64 `json:"lon"`
}

type ListUserToken struct {
	ListUserToken []UserToken `json:"tokens"`
}

func Connect() error {
	var err error
	db, err = sql.Open("postgres", fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", dbhost, dbport, dbuser, dbpass, dbname))
	if err != nil {
		return err
	}
	if err = db.Ping(); err != nil {
		return err
	}
	return nil
}

func getAllToken() ([]UserToken, error) {
	result := []UserToken{}

	rows, err := db.Query("SELECT token, lat, lon FROM device_tokens WHERE lat IS NOT NULL AND lon IS NOT NULL AND lat != '' AND lon != ''")
	if err != nil {
		return result, err
	}
	defer rows.Close()

	for rows.Next() {
		u := UserToken{}
		if err := rows.Scan(&u.Token, &u.Lat, &u.Lon); err != nil {
			return result, err
		}
		result = append(result, u)
	}
	return result, nil
}

func getPolygon(y int, m int, d int, ch chan []PolygonDB) {
	result := []PolygonDB{}
	tgl := fmt.Sprintf("'%d-%d-%d'", y, m, d)
	sql := fmt.Sprintf("SELECT severity, polygons FROM alert_signature_bmkg WHERE severity IS NOT NULL AND (guid = 'fakealertxyz' OR guid = 'fakealert123') AND effective::date = (%s)::date", tgl)

	rows, err := db.Query(sql)
	if err != nil {
		fmt.Println("error: ", err)
		ch <- result
	}
	defer rows.Close()

	for rows.Next() {
		u := PolygonDB{}
		if err := rows.Scan(&u.Severity, &u.Polygon); err != nil {
			ch <- result
		}
		result = append(result, u)
	}
	ch <- result
}

func getPointFromRaster(d []PolygonDB, rasterUrl string, ch chan map[string][][][2]float64) {
	log.Println(d)
	points := make(map[string][][][2]float64)

	for j := 0; j < len(d); j++ {
		e := strings.Split(d[j].Polygon, " ")
		rings := ""

		for i := 0; i < len(e); i++ {
			g := strings.Split(e[i], ",")
			if rings != "" {
				if len(g) > 1 {
					rings = rings + ","
				}
			}

			if len(g) > 1 {
				rings = rings + "[" + g[1] + "," + g[0] + "]"
			}
		}
		rings = "[[" + rings + "]]"
		severity := d[j].Severity

		h := histogram(rings, rasterUrl)
		points[severity] = append(points[severity], h)
	}
	ch <- points
}

func histogram(rings string, rasterUrl string) [][2]float64 {
	polygonAlerts := [][2]float64{}

	// uri := `http://inarisk1.bnpb.go.id:6080/arcgis/rest/services/inaRISK/INDEKS_BAHAYA_BANJIR/ImageServer/getSamples`

	dataUrl := url.Values{}
	dataUrl.Set("geometry", `{"rings":`+rings+`,"spatialReference":{"wkid":4326}}`)
	dataUrl.Set("geometryType", "esriGeometryPolygon")
	dataUrl.Set("returnFirstValueOnly", "false")
	dataUrl.Set("sampleDistance", "0")
	dataUrl.Set("sampleCount", "100000")
	dataUrl.Set("f", "pjson")

	req, _ := http.NewRequest("POST", rasterUrl, strings.NewReader(dataUrl.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(dataUrl.Encode())))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("whiips:", err)
		panic(err)
	}
	data := bytes.NewBuffer(body)

	t := new(ListSample)
	err = json.Unmarshal(data.Bytes(), &t)
	if err != nil {
		fmt.Println("whoops:", err)
		panic(err)
	}

	for i := 0; i < len(t.Samples); i++ {
		if val, _ := strconv.ParseFloat(t.Samples[i].Value, 64); val > 0 {
			p := [2]float64{
				t.Samples[i].Location.X,
				t.Samples[i].Location.Y,
			}
			polygonAlerts = append(polygonAlerts, p)
		}
	}
	return polygonAlerts
}

func getInsideToken(data map[string][][][2]float64, allToken []UserToken, ch chan map[string][]string) {
	log.Println(data)
	result := make(map[string][]string)
	flag := true
	for k := 0; k < len(allToken); k++ {
		flag = true
		for x := range data {
			for i := 0; i < len(data[x]) && flag; i++ {
				if len(data[x][i]) > 0 {
					p := data[x][i]
					for j := 0; j < len(p); j++ {
						r := countDistance(allToken[k].Lat, allToken[k].Lon, p[j][1], p[j][0])
						if r <= minDistance {
							result[x] = append(result[x], allToken[k].Token)
							flag = false
							break
						}
					}
				}
			}
		}
	}
	ch <- result
}

func countDistance(lat1 float64, lon1 float64, lat2 float64, lon2 float64) float64 {
	x := 69.1 * (lat2 - lat1)
	y := 69.1 * (lon2 - lon1) * math.Cos(lat1/57.3)
	distance := math.Sqrt(x*x+y*y) * 1609
	return distance
}

func prepareMessage(title string) *messaging.MulticastMessage {
	oneHour := time.Duration(1) * time.Hour
	badge := 42
	message := &messaging.MulticastMessage{
		Notification: &messaging.Notification{
			Title: title,
			Body:  "",
		},
		Android: &messaging.AndroidConfig{
			TTL: &oneHour,
		},
		APNS: &messaging.APNSConfig{
			Payload: &messaging.APNSPayload{
				Aps: &messaging.Aps{
					Badge: &badge,
				},
			},
		},
	}
	return message
}

// func subscribeToTopic(ctx context.Context, client *messaging.Client, topic string, tokens []string) {
// 	_, err := client.SubscribeToTopic(ctx, tokens, topic)
// 	if err != nil {
// 		log.Fatalln(err)
// 	}
// 	// fmt.Println(response.SuccessCount, "tokens were subscribed successfully")
// }
// func unsubscribeFromTopic(ctx context.Context, client *messaging.Client, topic string, tokens []string) {
// 	_, err := client.UnsubscribeFromTopic(ctx, tokens, topic)
// 	if err != nil {
// 		log.Fatalln(err)
// 	}
// 	// fmt.Println(response.SuccessCount, "tokens were unsubscribed successfully")
// }

func sendMulticastAndHandleErrors(ctx context.Context, client *messaging.Client, message *messaging.MulticastMessage, tokens []string) {
	br, err := client.SendMulticast(context.Background(), message)
	if err != nil {
		log.Fatalln(err)
	}

	if br.FailureCount > 0 {
		var failedTokens []string
		for idx, resp := range br.Responses {
			if !resp.Success {
				failedTokens = append(failedTokens, tokens[idx])
			}
		}
		fmt.Printf("List of tokens that caused failures: %v\n", failedTokens)
	}
}

func sentAlert(ctx context.Context, client *messaging.Client, tokens map[string][]string, when string, bahaya string) {
	status := ""
	potensi := ""
	if bahaya == "banjir" {
		potensi = "Banjir"
	} else if bahaya == "bandang" {
		potensi = "Banjir Bandang"
	} else {
		potensi = "Tanah Longsor"
	}
	for x := range tokens {
		start := 0
		end := 500
		if end > len(tokens[x]) {
			end = len(tokens[x])
		}
		if len(tokens[x]) > 0 {
			// fmt.Println("trying to subscribe client..")
			// subscribeToTopic(ctx, client, "inarisk", tokens[x])

			if x == "Moderate" {
				status = "Waspada"
			} else if x == "Severe" {
				status = "Siaga"
			} else {
				status = "Bahaya"
			}

			title := status + ", Potensi Bencana " + potensi + " " + when + " di Sekitar Lokasi Anda."
			message := prepareMessage(title)
			token := tokens[x][start:end]

			for len(token) > 0 {
				sendMulticastAndHandleErrors(ctx, client, message, token)
				start = end
				end = end + 500
				token = tokens[x][start:end]
			}

			// response, err := client.Send(ctx, message)
			// if err != nil {
			// 	log.Fatalln(err)
			// }
			// fmt.Println("trying to unsubscribe client..")
			// unsubscribeFromTopic(ctx, client, "inarisk", tokens[x])
			// fmt.Println("Successfully sent message:", response)
			fmt.Println("Successfully sent message:")
		}
	}
}

func initializeFCM() *firebase.App {
	opt := option.WithCredentialsFile("bnpbinarisk.json")
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		log.Fatalf("error initializing app: %v\n", err)
	}
	return app
}

func scheduledAlert() {
	log.Println("start...")
	log.Println("get all tokens...")
	allToken, _ := getAllToken()

	t := time.Now()
	t1 := t.AddDate(0, 0, 1)
	t2 := t.AddDate(0, 0, 2)
	todayCh := make(chan []PolygonDB)
	tomorrowCh := make(chan []PolygonDB)
	dayAfterCh := make(chan []PolygonDB)

	todayPointCh := make(chan map[string][][][2]float64)
	tomorrowPointCh := make(chan map[string][][][2]float64)
	dayAfterPointCh := make(chan map[string][][][2]float64)

	todayTokenCh := make(chan map[string][]string)
	tomorrowTokenCh := make(chan map[string][]string)
	dayAfterTokenCh := make(chan map[string][]string)

	log.Println("get polygon...")
	go getPolygon(t.Year(), int(t.Month()), t.Day(), todayCh)
	go getPolygon(t1.Year(), int(t1.Month()), t1.Day(), tomorrowCh)
	go getPolygon(t2.Year(), int(t2.Month()), t2.Day(), dayAfterCh)
	todayPolygon, tomorrowPolygon, dayAfterTomorrowPolygon := <-todayCh, <-tomorrowCh, <-dayAfterCh

	// opts := []option.ClientOption{option.WithCredentialsFile("bnpbinarisk.json")}
	ctx := context.Background()
	app := initializeFCM()
	client, err := app.Messaging(ctx)

	if err != nil {
		log.Println("error getting Messaging client: %v", err)
		panic(err)
	}

	raster := map[string]string{
		"banjir":  `http://inarisk1.bnpb.go.id:6080/arcgis/rest/services/inaRISK/INDEKS_BAHAYA_BANJIR/ImageServer/getSamples`,
		"bandang": `http://inarisk1.bnpb.go.id:6080/arcgis/rest/services/inaRISK/INDEKS_BAHAYA_BANJIR_BANDANG/ImageServer/getSamples`,
		"longsor": `http://inarisk1.bnpb.go.id:6080/arcgis/rest/services/inaRISK/INDEKS_BAHAYA_TANAH_LONGSOR/ImageServer/getSamples`,
	}

	for x := range raster {
		log.Println("raster: ", raster[x])
		log.Println("get point...")
		go getPointFromRaster(todayPolygon, raster[x], todayPointCh)
		go getPointFromRaster(tomorrowPolygon, raster[x], tomorrowPointCh)
		go getPointFromRaster(dayAfterTomorrowPolygon, raster[x], dayAfterPointCh)
		todayPoint, tomorrowPoint, dayAfterPoint := <-todayPointCh, <-tomorrowPointCh, <-dayAfterPointCh

		log.Println("get user near point today...")
		go getInsideToken(todayPoint, allToken, todayTokenCh)
		log.Println("get user near point tomorrow...")
		go getInsideToken(tomorrowPoint, allToken, tomorrowTokenCh)
		log.Println("get user near point lusa...")
		go getInsideToken(dayAfterPoint, allToken, dayAfterTokenCh)
		todayToken, tomorrowToken, dayAfterToken := <-todayTokenCh, <-tomorrowTokenCh, <-dayAfterTokenCh

		if len(todayToken) > 0 {
			fmt.Println("trying to sent message hari ini..")
			go sentAlert(ctx, client, todayToken, "Hari Ini", x)
		} else {
			fmt.Println("token hari ini kosong..")
		}
		if len(tomorrowToken) > 0 {
			fmt.Println("trying to sent message esok hari..")
			go sentAlert(ctx, client, tomorrowToken, "Esok Hari", x)
		} else {
			fmt.Println("token esok kosong..")
		}
		if len(dayAfterToken) > 0 {
			fmt.Println("trying to sent message lusa..")
			go sentAlert(ctx, client, dayAfterToken, "Dalam 2 Hari Kedepan", x)
		} else {
			fmt.Println("token lusa kosong..")
		}
	}
}

func main() {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	if err := Connect(); err != nil {
		log.Fatal(err)
	}

	c := cron.New()
	c.AddFunc("0 */10 * * * *", scheduledAlert)
	c.Start()

	// go scheduledAlert()

	for {
		select {
		case <-interrupt:
			os.Exit(0)
		}
	}
}
