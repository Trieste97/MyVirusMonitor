function create_chart(data)  {
    var dataPoints = []
    first_av = "";
    for( var i = 0; i < data['file_info'][0][2].length; i++ ) {
        first_av += data['file_info'][0][2][i] + "<br>";
    }
    dataPoints.push({ x: new Date(data['file_info'][0][0]), y: data['file_info'][0][3], av_list: first_av});

    for( var i = 1; i < data['file_info'].length; i++ ) {
        current_av = "";
        for( var j = 0; j < data['file_info'][i][2].length; j++ ) {
            current_av += data['file_info'][i][2][j] + "<br>";
        }
        dataPoints.push({ x: new Date(data['file_info'][i][0]), y: data['file_info'][i][3], av_list: current_av});
    }

    var chart = new CanvasJS.Chart("chartContainer", {
        animationEnabled: true,
        theme: "light2",
        title: {
            text: data['name']
        },
        axisX: {
            valueFormatString: "DD-MM-YYYY"
        },
        axisY: {
            includeZero: true
        },
        data: [{
            type: "line",
            toolTipContent: "{x}<hr/>{av_list}",
            dataPoints: dataPoints
        }]
    });
    chart.render();
}