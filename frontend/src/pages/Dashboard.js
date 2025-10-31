import React, { useState, useEffect } from 'react';
import { Grid, Paper, Typography, Box, Card, CardContent, CircularProgress } from '@mui/material';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';

// Mock data - in a real app, this would come from API calls
const mockAlertData = [
  { name: 'Malware', value: 12, color: '#ff5252' },
  { name: 'Phishing', value: 19, color: '#ff9800' },
  { name: 'Brute Force', value: 8, color: '#2196f3' },
  { name: 'Data Exfil', value: 5, color: '#9c27b0' },
  { name: 'Ransomware', value: 2, color: '#f44336' }
];

const mockPlaybookData = [
  { name: 'Running', value: 3, color: '#4caf50' },
  { name: 'Completed', value: 24, color: '#2196f3' },
  { name: 'Failed', value: 2, color: '#f44336' }
];

const mockTimelineData = [
  { day: 'Mon', alerts: 5 },
  { day: 'Tue', alerts: 8 },
  { day: 'Wed', alerts: 12 },
  { day: 'Thu', alerts: 7 },
  { day: 'Fri', alerts: 10 },
  { day: 'Sat', alerts: 3 },
  { day: 'Sun', alerts: 4 }
];

function Dashboard() {
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({
    totalAlerts: 0,
    criticalAlerts: 0,
    activePlaybooks: 0,
    resolvedIncidents: 0
  });

  useEffect(() => {
    // Simulate API call
    const fetchData = async () => {
      // In a real app, this would be an API call
      setTimeout(() => {
        setStats({
          totalAlerts: 46,
          criticalAlerts: 8,
          activePlaybooks: 3,
          resolvedIncidents: 38
        });
        setLoading(false);
      }, 1000);
    };

    fetchData();
  }, []);

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '80vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Security Dashboard
      </Typography>

      {/* Summary Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ bgcolor: 'primary.dark' }}>
            <CardContent>
              <Typography variant="h6" color="white">Total Alerts</Typography>
              <Typography variant="h3" color="white">{stats.totalAlerts}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ bgcolor: 'error.dark' }}>
            <CardContent>
              <Typography variant="h6" color="white">Critical Alerts</Typography>
              <Typography variant="h3" color="white">{stats.criticalAlerts}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ bgcolor: 'success.dark' }}>
            <CardContent>
              <Typography variant="h6" color="white">Active Playbooks</Typography>
              <Typography variant="h3" color="white">{stats.activePlaybooks}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ bgcolor: 'info.dark' }}>
            <CardContent>
              <Typography variant="h6" color="white">Resolved Incidents</Typography>
              <Typography variant="h3" color="white">{stats.resolvedIncidents}</Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Charts */}
      <Grid container spacing={3}>
        <Grid item xs={12} md={8}>
          <Paper sx={{ p: 2, height: '100%' }}>
            <Typography variant="h6" gutterBottom>
              Alert Timeline (Last 7 Days)
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={mockTimelineData}>
                <XAxis dataKey="day" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="alerts" fill="#8884d8" />
              </BarChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>
        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 2, height: '100%' }}>
            <Typography variant="h6" gutterBottom>
              Alert Types
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={mockAlertData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                >
                  {mockAlertData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>
        <Grid item xs={12}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Playbook Execution Status
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={mockPlaybookData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                  label={({ name, value }) => `${name}: ${value}`}
                >
                  {mockPlaybookData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
}

export default Dashboard;