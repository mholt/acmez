{ 
    "subject": {{ toJson .Subject }},
    "sans": [{
        "type": "permanentIdentifier", 
        "value": {{ toJson .Subject.CommonName }}
    }]
}