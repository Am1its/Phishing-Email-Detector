var API_URL = "https://amitoved.pythonanywhere.com/scan"; 

function buildAddOn(e) {
  var accessToken = e.messageMetadata.accessToken;
  var messageId = e.messageMetadata.messageId;
  GmailApp.setCurrentMessageAccessToken(accessToken);
  
  var message = GmailApp.getMessageById(messageId);
  var body = message.getPlainBody();

  var options = {
    "method": "post",
    "contentType": "application/json",
    "payload": JSON.stringify({ "text": body }),
    "muteHttpExceptions": true
  };

  var response = UrlFetchApp.fetch(API_URL, options);
  if (response.getResponseCode() !== 200) {
    return createErrorCard("Server Error", "Status: " + response.getResponseCode());
  }

  var json = JSON.parse(response.getContentText());
  return createResultCard(json);
}

function createResultCard(json) {
  var header = CardService.newCardHeader();
  var section = CardService.newCardSection();

  if (json.is_phishing) {
    var title = "🚨 Phishing Risk: " + json.risk_score + "%";
    
    header.setTitle(title)
          .setSubtitle("High threat level detected")
          .setImageStyle(CardService.ImageStyle.CIRCLE);
    
    json.threats.forEach(function(t) {
      section.addWidget(CardService.newTextParagraph().setText("• " + t));
    });
  } else {
    header.setTitle("✅ Safe Email")
          .setSubtitle("Risk Score: 0%");
  }

  return CardService.newCardBuilder()
      .setHeader(header)
      .addSection(section)
      .build();
}

function createErrorCard(title, msg) {
  return [CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle(title))
    .addSection(CardService.newCardSection().addWidget(CardService.newTextParagraph().setText(msg)))
    .build()];
}