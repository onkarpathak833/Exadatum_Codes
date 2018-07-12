package Project1.TwitterStreaming;

import kafka.consumer.Consumer;
import kafka.consumer.ConsumerIterator;
import kafka.consumer.KafkaStream;
import kafka.javaapi.consumer.ConsumerConnector;
import twitter4j.JSONArray;
import twitter4j.JSONException;
import twitter4j.JSONObject;

import org.apache.avro.Schema;
import org.apache.avro.Schema.Field;
import org.apache.avro.file.DataFileWriter;
import org.apache.avro.generic.GenericDatumReader;
import org.apache.avro.generic.GenericDatumWriter;
import org.apache.avro.generic.GenericRecord;
import org.apache.avro.io.BinaryDecoder;
import org.apache.avro.io.DatumReader;
import org.apache.avro.io.Decoder;
import org.apache.avro.io.DecoderFactory;
import org.apache.avro.io.Encoder;
import org.apache.commons.io.FileUtils;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;

import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * Consumer created to take twitter data
 */
public class KafkaMessageConsumer {

	public static final String tweetSchema = "{\"type\":\"record\",\"name\":\"TweetJson\",\"fields\":[{\"default\":null,\"type\":[\"null\",\"string\"],\"name\":\"CreationTime\"},{\"default\":null,\"type\":[\"null\",\"string\"],\"name\":\"TweetId\"},{\"default\":null,\"type\":[\"null\",\"bytes\"],\"name\":\"TweetText\"},{\"default\":null,\"type\":[\"null\",\"string\"],\"name\":\"TwitterUser\"}]}";

	public static final String userSchema = "{\"type\":\"record\",\"name\":\"TweetJson\",\"fields\":[{\"default\":null,\"type\":[\"null\",\"string\"],\"name\":\"UserId\"},{\"default\":null,\"type\":[\"null\",\"string\"],\"name\":\"UserName\"},{\"default\":null,\"type\":[\"null\",\"string\"],\"name\":\"Location\"},{\"default\":null,\"type\":[\"null\",\"string\"],\"name\":\"Followers\"},{\"default\":null,\"type\":[\"null\",\"string\"],\"name\":\"FriendsCount\"}]}";
	
	public static JSONArray processRawTweet(String tweet){
		
		JSONArray dataArray = new JSONArray();
		JSONObject twitterData = new JSONObject();
		JSONObject tweetUserData = new JSONObject();
		JSONObject tweetJson;
		try {
		tweetJson = new JSONObject(tweet);
		
        String creationTime = tweetJson.getString("created_at");
        String tweetId = tweetJson.getString("id");
		String tweetText = tweetJson.getString("text");
		String userData = tweetJson.getString("user");
		JSONObject userJson = new JSONObject(userData);
		String userId = userJson.getString("id");
		tweetJson.remove("user");
		
		twitterData.put("CreationTime", creationTime);
		twitterData.put("TweetId", tweetId);
		twitterData.put("TweetText", tweetText);
		twitterData.put("TwitterUser", userId);
		
		
		String userName = userJson.getString("name");
		String userLocation = userJson.getString("location");
		String userFollowers = userJson.getString("followers_count");
		String userFriendsCounts = userJson.getString("friends_count");
		
		tweetUserData.put("UserId", userId);
		tweetUserData.put("UserName", userName);
		tweetUserData.put("Location", userLocation);
		tweetUserData.put("Followers", userFollowers);
		tweetUserData.put("FriendsCount", userFriendsCounts);
		
		System.out.println("Tweet Data Is : "+twitterData);
		System.out.println("User Data Is : "+tweetUserData);
		dataArray.put(0, twitterData);
		dataArray.put(1, tweetUserData);
		} catch (JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return dataArray;
	}
	
	
	public static JSONArray formatFields(JSONObject jsonObject, String schemaString){
		
		JSONArray formatArray = new JSONArray();
		
		Schema schema = Schema.parse(schemaString);
		List<Field> columnNames = schema.getFields();
		String recordString = "{";
		boolean isLastColumn = false;
		
		for (int j = 0; j < columnNames.size(); j++) {
			if (j == columnNames.size() - 1) {
				isLastColumn = true;
			}
			Object value = null;
			try {
				if(jsonObject.has(columnNames.get(j).name().toString())){
					value = jsonObject.get(columnNames.get(j).name().toString());
				}
				
			} catch (JSONException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			if (columnNames.get(j).schema().toString().equals("\"string\"")) {
				value = "\"" + value + "\"";
			}
			recordString = recordString + "\"" + columnNames.get(j).name().toString() + "\"" + ":" + value;
			if (!isLastColumn) {
				recordString = recordString + ",";
			}
			if (isLastColumn) {
				recordString = recordString + "}";
			}
		}
		System.out.println("Formatted Json Data : "+recordString);
		formatArray.put(recordString);
		
		return formatArray;
	} 
	
	
	public static byte[] convertJsonToAvro(JSONArray jsonArray, String schemaString) throws Exception{
		
		
		DataFileWriter<GenericRecord> writer = null;
		Encoder encoder = null;
		ByteArrayOutputStream output = null;
		String data = "";
		try {
			Schema schema = new Schema.Parser().parse(schemaString);
			DatumReader<GenericRecord> reader = new GenericDatumReader<GenericRecord>(schema);
			// input = new ByteArrayInputStream(json.getBytes());
			output = new ByteArrayOutputStream();

			writer = new DataFileWriter<GenericRecord>(new GenericDatumWriter<GenericRecord>());
			GenericDatumWriter<Object> writer1 = new GenericDatumWriter<Object>(schema);
			writer.create(schema, output);
			for (int i = 0; i < jsonArray.length(); i++) {
				String object = jsonArray.get(i).toString();
				InputStream input = new ByteArrayInputStream(object.getBytes());
				DataInputStream din = new DataInputStream(input);
				Decoder decoder = DecoderFactory.get().jsonDecoder(schema, din);
				
				Object datum = null;
				datum = reader.read(null, decoder);
				data = datum.toString();
				writer.append((GenericRecord) datum);
			}

			
		
			writer.flush();

		} catch (Exception e) {
			System.out.println(e);
			System.out.println(data);

		}
		
		return output.toByteArray();
	}
	
	public static boolean putJsonTos3(JSONArray dataArray){
		
		JSONObject tweetData = null;
		JSONObject userData = null;
		try {
			tweetData = dataArray.getJSONObject(0);
			InputStream tweetStream = new ByteArrayInputStream(tweetData.toString().getBytes());
			userData = dataArray.getJSONObject(1);
			InputStream userStream = new ByteArrayInputStream(userData.toString().getBytes());
			//AmazonS3 s3Client = AmazonS3ClientBuilder.defaultClient();
			AmazonS3Client client = new AmazonS3Client(
				    new BasicAWSCredentials("AKIAJRRIQ2FJPTFHB6XA", "vs6LnDtZgtLc179BKVUqcjqoka2isQftKZQ3M+oK"));
			Timestamp ts = new Timestamp(System.currentTimeMillis());
			File tweetFile = File.createTempFile("jsonTweet", "json");
			tweetFile.createNewFile();
		
			String tweetTextData = "";
			Iterator itr = tweetData.keys();
			while(itr.hasNext()){
				String key = itr.next().toString();
				tweetTextData = tweetTextData+"*****"+tweetData.getString(key);
				
			}
			tweetTextData = tweetTextData.substring(5, tweetTextData.length());
			String userTextData = "";
			Iterator userItr = userData.keys();
			while(userItr.hasNext()){
				String key = userItr.next().toString();
				userTextData=userTextData+"*****"+userData.getString(key);
			}
			
			userTextData = userTextData.substring(5, userTextData.length());
			
			FileUtils.writeStringToFile(tweetFile, tweetData.toString());
			client.putObject("techgig-twitter-data", "TweetJson/"+ts.toString(), tweetTextData);
			
			File userFile = File.createTempFile("jsonUsers", "json");
			userFile.createNewFile();
			FileUtils.writeStringToFile(userFile, userData.toString());
			client.putObject("techgig-twitter-data", "UserJson/"+ts.toString(), userTextData);
		} catch (JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		return false;
	}
	
	public static boolean putAvroToS3(byte[] avroArray, String dirName) throws IOException{
		
		AmazonS3Client client = new AmazonS3Client(
			    new BasicAWSCredentials("AKIAJRRIQ2FJPTFHB6XA", "vs6LnDtZgtLc179BKVUqcjqoka2isQftKZQ3M+oK"));
		Timestamp ts = new Timestamp(System.currentTimeMillis());
		File file = File.createTempFile("avro", "data");
		file.createNewFile();
		FileUtils.writeByteArrayToFile(file, avroArray);
		client.putObject("techgig-twitter-data", dirName+"/"+ts.toString(), file);
		
		return true;
	}
	
  public static void main(String[] args) throws IOException {
    Properties config = new Properties();
    config.put("zookeeper.connect", "localhost:2181");
    config.put("group.id", "default");
    config.put("partition.assignment.strategy", "roundrobin");
    config.put("bootstrap.servers", "localhost:9092");
    config.put("value.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
    config.put("key.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
    kafka.consumer.ConsumerConfig consumerConfig = new kafka.consumer.ConsumerConfig(config);

    ConsumerConnector consumerConnector = Consumer.createJavaConsumerConnector(consumerConfig);

    Map<String, Integer> topicCountMap = new HashMap<String, Integer>();
    topicCountMap.put("CAR_DATA", 1);

    Map<String, List<KafkaStream<byte[], byte[]>>> consumerMap = consumerConnector.createMessageStreams(topicCountMap);

    List<KafkaStream<byte[], byte[]>> streamList = consumerMap.get("CAR_DATA");

    KafkaStream<byte[], byte[]> stream = streamList.get(0);

    ConsumerIterator<byte[], byte[]> iterator = stream.iterator();
    while(iterator.hasNext()) {
    	String messageData = new String(iterator.next().message());
      //System.out.println(new String(iterator.next().message()));
    	//System.out.println(messageData);
    	JSONArray tweetArrays = processRawTweet(messageData);
    	//putJsonTos3(tweetArrays);
    	try {
			JSONArray tweetFormatArray = formatFields(tweetArrays.getJSONObject(0), tweetSchema);
			System.out.println(tweetFormatArray);
			JSONArray userFormatArray = formatFields(tweetArrays.getJSONObject(1), userSchema);
			System.out.println(userFormatArray);
		} catch (JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
    }

  }

  public static void processRecords(Map<String, ConsumerRecords<String, String>> records) {
    List<ConsumerRecord<String, String>> messages = records.get("CAR_DATA").records();
    if(messages != null) {
      for (ConsumerRecord<String, String> next : messages) {
        try {
          System.out.println(next.value());
        } catch (Exception e) {
          e.printStackTrace();
        }
      }
    } else {
      System.out.println("No messages");
    }
  }
}
